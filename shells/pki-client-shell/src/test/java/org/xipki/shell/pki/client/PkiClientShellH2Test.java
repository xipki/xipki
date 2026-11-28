// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.pki.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.CRLEntry;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.gateway.cmp.CmpControl;
import org.xipki.ca.gateway.cmp.CmpHttpServlet;
import org.xipki.ca.gateway.cmp.CmpProtocolConf;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.ca.gateway.scep.CaNameScepSigners;
import org.xipki.ca.gateway.scep.ScepControl;
import org.xipki.ca.gateway.scep.ScepHttpServlet;
import org.xipki.ca.gateway.scep.ScepProtocolConf;
import org.xipki.ca.gateway.scep.ScepResponder;
import org.xipki.ca.gateway.test.GatewayTestEnv;
import org.xipki.ca.gateway.test.ServletTestServer;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.Base64;
import org.xipki.codec.json.JsonParser;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.auth.SimpleRequestorAuthenticator;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.pkcs12.X509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.shell.security.SecurityShellMain;
import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.misc.NameId;

import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The commands of the PKI client shell, executed as in the CLI (picocli, root command of the
 * module), with the configuration in {@code xipki/etc} of a temporary shell home
 * ({@code cmp-client.json}, {@code curl.json}, {@code security.json} with the in-memory HSM
 * xihsm), against the CA of {@link GatewayTestEnv} (in-memory H2 databases): CMP and SCEP
 * gateway in {@link ServletTestServer}, OCSP responder ({@link OcspServer}, store
 * {@code xipki-ca-db} on the CA database) in the HTTP server of the JDK.
 *
 * @author Lijun Liao (xipki)
 */
public class PkiClientShellH2Test {

  private static final String CA = GatewayTestEnv.CA;

  private static final String PROFILE = GatewayTestEnv.PROFILE;

  private static final String PWD = "CHANGEIT";

  private static final String SIG_ALGO = "SHA256withECDSA";

  private static final String PBM_USER = "cmp-user";

  private static final String PBM_PASSWORD = "cmp-password";

  private static final String SCEP_PROFILE = "tls";

  private static final String SETUP_PROFILES =
      "assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/ca-setup/certprofile";

  private static final AtomicInteger COUNTER = new AtomicInteger();

  private static GatewayTestEnv env;

  private static CaManagerImpl caManager;

  private static ServletTestServer cmpServer;

  private static ServletTestServer scepServer;

  private static OcspServer ocspServer;

  private static HttpServer ocspHttpServer;

  private static Path work;

  private static X509Cert caCert;

  private static Path caCertFile;

  /** PKCS#12 keystore of the CMP requestor, permitted by its certificate. */
  private static Path requestorP12;

  @BeforeClass
  public static void init() throws Exception {
    Path home = Files.createTempDirectory("xipki-pki-client-shell");
    work = Files.createDirectories(home.resolve("work"));

    env = new GatewayTestEnv();
    caManager = env.ca().caManager();
    caCert = env.ca().caCert();
    caCertFile = file("ca.der");
    Files.write(caCertFile, caCert.getEncoded());
    SecurityFactory securityFactory = env.ca().securities().securityFactory();

    initCmp(home, securityFactory);
    initScep(securityFactory);
    initOcsp();

    Path etc = home.resolve("xipki/etc");
    Files.writeString(etc.resolve("curl.json"), "{\"hostConfs\": []}");
    Path pkcs11Conf = Files.createDirectories(home.resolve("xipki/security"))
        .resolve("pkcs11.json");
    Files.writeString(pkcs11Conf, "{\"modules\": [{\"name\": \"default\","
        + " \"readonly\": false, \"user\": \"CKU_USER\", \"numSessions\": 10,"
        + " \"nativeLibraries\": [{\"path\": \"xihsm:mem:vendor=xihsm\"}],"
        + " \"passwordSets\": [{\"passwords\": [\"123456\"]}]}]}");
    Files.writeString(etc.resolve("security.json"), "{\"pkcs11Conf\": {\"file\": \""
        + pkcs11Conf.toAbsolutePath().toString().replace("\\", "/") + "\"}}");
    System.setProperty("org.xipki.shell.home", home.toString());
  }

  private static void initCmp(Path home, SecurityFactory securityFactory) throws Exception {
    ConcurrentSigner responderSigner = newSigner(securityFactory, newKeystore("P256"));
    requestorP12 = newKeystore("P256");

    Path requestorsConf = env.ca().workDir().resolve("cmp-requestors.json");
    Files.writeString(requestorsConf, "{\"passwords\": [{\"user\": \"" + PBM_USER
        + "\", \"password\": \"" + PBM_PASSWORD + "\",\n"
        + "  \"protocols\": [\"CMP\"], \"permissions\": [\"ALL\"],\n"
        + "  \"caProfiles\": [{\"ca\": \"ALL\", \"profiles\": [\"ALL\"]}]}],\n"
        + "\"certs\": [{\"cert\": {\"binary\": \""
        + Base64.encodeToString(certOf(requestorP12).getEncoded()) + "\"},\n"
        + "  \"protocols\": [\"CMP\"], \"permissions\": [\"ALL\"],\n"
        + "  \"caProfiles\": [{\"ca\": \"ALL\", \"profiles\": [\"ALL\"]}]}]}\n");
    SimpleRequestorAuthenticator authenticator = new SimpleRequestorAuthenticator();
    authenticator.init(requestorsConf.toString(), null);

    // as in the shipped cmp-gateway.json
    CmpControl cmpControl = new CmpControl(CmpProtocolConf.CmpControlConf.parse(
        JsonParser.parseMap("{\"messageTimeBias\": 300, \"confirmWaitTime\": 300,"
            + " \"requestSigAlgos\": [\"RSA-SHA256\", \"ECDSA-SHA256\"],"
            + " \"requestPbmMacs\": [\"HMAC-SHA256\"], \"requestPbmOwfs\": [\"SHA256\"],"
            + " \"responsePbmMac\": \"HMAC-SHA256\", \"responsePbmOwf\": \"SHA256\","
            + " \"responsePbmIterationCount\": 10240,"
            + " \"requestPbmMaxIterationCount\": 100000}", false)));
    CmpResponder responder = new CmpResponder(cmpControl, env.sdk(), securityFactory,
        new CaNameSigners(responderSigner, null), authenticator, env.popControl());
    cmpServer = new ServletTestServer("/cmp", new CmpHttpServlet(false, null, responder)::service,
        null);

    Path etc = Files.createDirectories(home.resolve("xipki/etc"));
    Files.writeString(etc.resolve("cmp-client.json"), "{\"sendRequestorCert\": true,"
        + " \"responder\": {\"url\": \"" + cmpServer.url() + "\", \"signature\": {"
        + "\"cert\": {\"binary\": \""
        + Base64.encodeToString(responderSigner.cert().x509Cert().getEncoded())
        + "\"}, \"signatureAlgos\": [\"" + SIG_ALGO + "\"]},"
        + " \"pbmMac\": {\"owfAlgos\": [\"SHA256\"], \"macAlgos\": [\"HMAC-SHA256\"]}}}");
  }

  private static void initScep(SecurityFactory securityFactory) throws Exception {
    // the shipped profiles: tls for the clients, scep-sign / scep-enc for the RA certificates
    addProfile(SCEP_PROFILE, "tls");
    addProfile("scep-sign", "scep-sign");
    addProfile("scep-enc", "scep-enc");
    Path signP12 = newKeystore("RSA2048");
    X509Cert signCert = issueRaCert(signP12, "scep-sign");
    Path encP12 = newKeystore("RSA2048");
    X509Cert encCert = issueRaCert(encP12, "scep-enc");

    ConcurrentSigner responderSigner = securityFactory.createSigner("pkcs12",
        new SignerConf("password=" + PWD + ",algo=SHA256withRSA,keystore=base64:"
            + Base64.encodeToString(Files.readAllBytes(signP12))), CertVariant.ofX509(signCert));
    ScepProtocolConf.CaNameDecryptorsConf decryptors = new ScepProtocolConf.CaNameDecryptorsConf(
        new GatewayConf.SignerConf("pkcs12", "password=" + PWD + ",keystore=base64:"
            + Base64.encodeToString(Files.readAllBytes(encP12)),
            List.of(FileOrBinary.ofBinary(encCert.getEncoded()))), null);

    Path requestorsConf = env.ca().workDir().resolve("scep-requestors.json");
    Files.writeString(requestorsConf, "{\"passwords\": [{\"user\": \"" + GatewayTestEnv.USER
        + "\", \"password\": \"" + GatewayTestEnv.PASSWORD + "\",\n"
        + "  \"protocols\": [\"SCEP\"], \"permissions\": [\"ALL\"],\n"
        + "  \"caProfiles\": [{\"ca\": \"ALL\", \"profiles\": [\"ALL\"]}]}]}\n");
    SimpleRequestorAuthenticator authenticator = new SimpleRequestorAuthenticator();
    authenticator.init(requestorsConf.toString(), null);

    ScepControl control = new ScepControl();
    control.setIncludeCaCert(true);
    control.setIncludeSignerCert(true);
    control.setSupportGetCrl(true);

    GatewayConf.CaProfilesControl caProfiles = new GatewayConf.CaProfilesControl(List.of(
        new GatewayConf.CaProfileConf("scep", CA, SCEP_PROFILE)));
    ScepResponder responder = new ScepResponder(control, env.sdk(), securityFactory,
        new CaNameScepSigners(new CaNameSigners(responderSigner, null), decryptors, null),
        authenticator, env.popControl(), caProfiles);
    scepServer = new ServletTestServer("/scep", new ScepHttpServlet(false, responder)::service,
        null);
  }

  private static void initOcsp() throws Exception {
    Path signerP12 = newKeystore("P256");
    String dbConf = env.ca().caDbConf().toAbsolutePath().toString().replace("\\", "/");
    Path conf = file("ocsp-responder.json");
    Files.writeString(conf, "{\"master\": true, \"unknownIssuerBehaviour\": \"malformedRequest\","
        + " \"datasources\": [{\"name\": \"cadb\", \"conf\": {\"file\": \"" + dbConf + "\"}}],"
        + " \"requestOptions\": [{\"name\": \"request1\", \"hashAlgorithms\": [\"SHA1\","
        + " \"SHA256\"], \"maxRequestListCount\": 10, \"maxRequestSize\": 4096,"
        + " \"nonce\": {\"maxLen\": 32, \"minLen\": 4, \"occurrence\": \"optional\"},"
        + " \"signatureRequired\": false, \"supportsHttpGet\": true,"
        + " \"validateSignature\": false, \"versions\": [\"v1\"]}],"
        + " \"responders\": [{\"name\": \"responder1\", \"inheritCaRevocation\": true,"
        + " \"mode\": \"RFC6960\", \"request\": \"request1\", \"response\": \"response1\","
        + " \"servletPaths\": [\"/\"], \"signer\": \"signer1\", \"stores\": [\"store1\"]}],"
        + " \"responseOptions\": [{\"name\": \"response1\", \"embedCertsMode\": \"CERT\","
        + " \"includeCerthash\": false, \"includeInvalidityDate\": false,"
        + " \"includeRevReason\": true, \"responderIdByName\": true}],"
        + " \"signers\": [{\"name\": \"signer1\", \"type\": \"pkcs12\", \"key\": \"password="
        + PWD + ",keystore=base64:" + Base64.encodeToString(Files.readAllBytes(signerP12))
        + "\"}],"
        + " \"stores\": [{\"name\": \"store1\", \"ignoreExpiredCert\": true,"
        + " \"ignoreNotYetValidCert\": true, \"includeArchiveCutoff\": false,"
        + " \"includeCrlId\": false, \"retentionInterval\": -1,"
        + " \"minNextUpdatePeriod\": \"1d\", \"unknownCertBehaviour\": \"unknown\","
        + " \"updateInterval\": \"10m\","
        + " \"source\": {\"datasource\": \"cadb\", \"type\": \"xipki-ca-db\", \"conf\": {}}}]}");
    ocspServer = new OcspServer(env.ca().workDir().toString());
    ocspServer.setSecurityFactory(env.ca().securities().securityFactory());
    ocspServer.setConfFile(conf.toString());
    ocspServer.init(true);
    Responder responder = ocspServer.getResponder("responder1");
    Assert.assertNotNull("responder1", responder);

    ocspHttpServer = HttpServer.create(
        new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    ocspHttpServer.createContext("/ocsp", exchange -> serveOcsp(exchange, responder));
    ocspHttpServer.start();
  }

  private static void serveOcsp(HttpExchange exchange, Responder responder) throws IOException {
    try {
      byte[] request;
      try (InputStream in = exchange.getRequestBody()) {
        request = in.readAllBytes();
      }
      byte[] response = ocspServer.answer(responder, request, false).response();
      exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
      exchange.sendResponseHeaders(200, response.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(response);
      }
    } finally {
      exchange.close();
    }
  }

  @AfterClass
  public static void shutdown() {
    System.clearProperty("org.xipki.shell.home");
    if (ocspHttpServer != null) {
      ocspHttpServer.stop(0);
    }
    if (ocspServer != null) {
      ocspServer.close();
    }
    if (cmpServer != null) {
      cmpServer.close();
    }
    if (scepServer != null) {
      scepServer.close();
    }
    if (env != null) {
      env.close();
    }
  }

  // ----- CMP -----

  @Test
  public void cmpCaCertAndCaCerts() throws Exception {
    Path der = file("cmp-ca.der");
    ok("cmp-cacert", "--ca", CA, "--out", der.toString());
    Assert.assertArrayEquals(caCert.getEncoded(), Files.readAllBytes(der));

    Path pem = file("cmp-cas.pem");
    ok("cmp-cacerts", "--ca", CA, "--out", pem.toString());
    Assert.assertEquals(caCert, X509Util.parseCert(pem.toFile()));
  }

  @Test
  public void cmpEnrollP12() throws Exception {
    // requestor authenticated by signature, request type cr
    Path p12 = newKeystore("P256");
    X509Cert cert = cmpEnrollP12(p12, "cr", signerP12Args());
    Assert.assertEquals(certOf(p12).publicKey(), cert.publicKey());

    // requestor authenticated by PBM (user / password), request type ir
    Path p12b = newKeystore("P256");
    X509Cert cert2 = cmpEnrollP12(p12b, "ir", signerPbmArgs());
    Assert.assertEquals(certOf(p12b).publicKey(), cert2.publicKey());

    // wrong PBM password
    assertFails(null, "cmp-enroll-p12", "--ca", CA, "--p12", p12b.toString(),
        "--password", PWD, "--subject", subject(), "--profile", PROFILE,
        "--out", file("x.der").toString(), "--signer-keyid", PBM_USER,
        "--signer-password", "wrong");
  }

  @Test
  public void cmpEnrollP12PasswordFromStdin() throws Exception {
    // without --password: the keystore password is read once from the standard input
    Path p12 = newKeystore("P256");
    Path out = file("stdin.der");
    okIn(PWD + "\n", "cmp-enroll-p12", "--ca", CA, "--p12", p12.toString(),
        "--subject", subject(), "--profile", PROFILE, "--out", out.toString(),
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
    Assert.assertEquals(certOf(p12).publicKey(), X509Util.parseCert(out.toFile()).publicKey());
  }

  @Test
  public void cmpCsrEnroll() throws Exception {
    Path p12 = newKeystore("P256");
    Path csr = file("cmp.csr");
    String subject = subject();
    sec("csr-p12", "--p12", p12.toString(), "--password", PWD, "--subject", subject,
        "--out", csr.toString());

    Path out = file("cmp-csr.pem");
    ok("cmp-csr-enroll", "--ca", CA, "--csr", csr.toString(), "--profile", PROFILE,
        "--outform", "pem", "--out", out.toString(), "--signer-p12", requestorP12.toString(),
        "--signer-password", PWD);
    X509Cert cert = X509Util.parseCert(out.toFile());
    Assert.assertEquals(X509Util.getCommonName(new X500Name(subject)),
        X509Util.getCommonName(cert.subject()));
    Assert.assertTrue(X509Util.issues(caCert, cert));
  }

  @Test
  public void cmpEnrollServerkeygen() throws Exception {
    Path p12Out = file("skg.p12");
    Path certOut = file("skg.der");
    ok("cmp-enroll-serverkeygen", "--ca", CA, "--subject", subject(), "--profile", PROFILE,
        "--p12-out", p12Out.toString(), "--password", PWD, "--cert-out", certOut.toString(),
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
    X509Cert cert = X509Util.parseCert(certOut.toFile());
    Assert.assertEquals(cert, certOf(p12Out));
  }

  @Test
  public void cmpEnrollP11() throws Exception {
    String label = "cmp-p11-" + COUNTER.incrementAndGet();
    sec("keypair-p11", "--keyspec", "P256", "--label", label);
    Path out = file("p11.der");
    ok("cmp-enroll-p11", "--ca", CA, "--slot", "0", "--key-label", label,
        "--subject", subject(), "--profile", PROFILE, "--out", out.toString(),
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
    Assert.assertTrue(X509Util.issues(caCert, X509Util.parseCert(out.toFile())));
  }

  @Test
  public void cmpRevokeUnsuspendAndCrl() throws Exception {
    X509Cert cert = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    Path certFile = file("rev.der");
    Files.write(certFile, cert.getEncoded());
    BigInteger serial = cert.serialNumber();

    String out = ok("cmp-revoke", "--ca", CA, "--ca-cert", caCertFile.toString(),
        "--cert", certFile.toString(), "--reason", "certificateHold",
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
    Assert.assertTrue(out, out.contains("revoked certificate"));
    Assert.assertEquals(CrlReason.CERTIFICATE_HOLD,
        caManager.getCert(CA, serial).revInfo().reason());

    ok("cmp-unsuspend", "--ca", CA, "--ca-cert", caCertFile.toString(),
        "--serial", "0x" + serial.toString(16),
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
    Assert.assertNull(caManager.getCert(CA, serial).revInfo());

    ok("cmp-revoke", "--ca", CA, "--ca-cert", caCertFile.toString(),
        "--serial", "0x" + serial.toString(16), "-r", "keyCompromise",
        "--signer-keyid", PBM_USER, "--signer-password", PBM_PASSWORD);
    Assert.assertEquals(CrlReason.KEY_COMPROMISE,
        caManager.getCert(CA, serial).revInfo().reason());

    caManager.generateCrlOnDemand(CA);
    Path crl = file("cmp.crl");
    ok("cmp-get-crl", "--ca", CA, "--out", crl.toString());
    Assert.assertTrue(crlContains(crl, serial));

    assertFails("is not permitted", "cmp-revoke", "--ca", CA,
        "--ca-cert", caCertFile.toString(), "--serial", "0x1", "-r", "removeFromCRL",
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
  }

  @Test
  public void cmpUpdateP12() throws Exception {
    X509Cert oldCert = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    Path oldCertFile = file("old.der");
    Files.write(oldCertFile, oldCert.getEncoded());

    Path newP12 = newKeystore("P256");
    Path out = file("updated.der");
    ok("cmp-update-p12", "--ca", CA, "--oldcert", oldCertFile.toString(),
        "--p12", newP12.toString(), "--password", PWD, "--out", out.toString(),
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
    X509Cert newCert = X509Util.parseCert(out.toFile());
    Assert.assertEquals(oldCert.subject(), newCert.subject());
    Assert.assertEquals(certOf(newP12).publicKey(), newCert.publicKey());
  }

  @Test
  public void cmpUpdateP12EmbedsPublicKey() throws Exception {
    X509Cert oldCert = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    Path oldCertFile = file("old2.der");
    Files.write(oldCertFile, oldCert.getEncoded());

    Path newP12 = newKeystore("P256");
    Path out = file("updated2.der");
    ok("cmp-update-p12", "--ca", CA, "--oldcert", oldCertFile.toString(),
        "--p12", newP12.toString(), "--password", PWD, "--embeds-publickey",
        "--out", out.toString(), "--signer-p12", requestorP12.toString(),
        "--signer-password", PWD);
    X509Cert newCert = X509Util.parseCert(out.toFile());
    Assert.assertEquals(oldCert.subject(), newCert.subject());
    Assert.assertEquals(certOf(newP12).publicKey(), newCert.publicKey());
  }

  @Test
  public void cmpUpdateP12KeepsOldKey() throws Exception {
    // --no-embeds-publickey: the CA certifies the public key of the old certificate
    X509Cert oldCert = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    Path oldCertFile = file("old3.der");
    Files.write(oldCertFile, oldCert.getEncoded());

    Path out = file("updated3.der");
    ok("cmp-update-p12", "--ca", CA, "--oldcert", oldCertFile.toString(),
        "--p12", newKeystore("P256").toString(), "--password", PWD, "--no-embeds-publickey",
        "--out", out.toString(), "--signer-p12", requestorP12.toString(),
        "--signer-password", PWD);
    Assert.assertEquals(oldCert.publicKey(), X509Util.parseCert(out.toFile()).publicKey());
  }

  @Test
  public void cmpUpdateP11() throws Exception {
    X509Cert oldCert = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    Path oldCertFile = file("old-p11.der");
    Files.write(oldCertFile, oldCert.getEncoded());

    String label = "cmp-up-p11-" + COUNTER.incrementAndGet();
    sec("keypair-p11", "--keyspec", "P256", "--label", label);
    Path out = file("updated-p11.der");
    ok("cmp-update-p11", "--ca", CA, "--oldcert", oldCertFile.toString(), "--slot", "0",
        "--key-label", label, "--out", out.toString(),
        "--signer-p12", requestorP12.toString(), "--signer-password", PWD);
    X509Cert newCert = X509Util.parseCert(out.toFile());
    Assert.assertEquals(oldCert.subject(), newCert.subject());
    Assert.assertNotEquals(oldCert.publicKey(), newCert.publicKey());
  }

  @Test
  public void cmpRequestAndResponseSaved() throws Exception {
    Path req = file("cacert.req");
    Path resp = file("cacert.resp");
    ok("cmp-cacert", "--ca", CA, "--out", file("ca2.der").toString(),
        "--req-out", req.toString(), "--resp-out", resp.toString());
    Assert.assertTrue(Files.size(req) > 0);
    Assert.assertTrue(Files.size(resp) > 0);
  }

  // ----- SCEP -----

  @Test
  public void scepCacert() throws Exception {
    Path out = file("scep-ca.der");
    ok("scep-cacert", "--url", scepUrl(), "--out", out.toString());
    Assert.assertArrayEquals(caCert.getEncoded(), Files.readAllBytes(out));
  }

  @Test
  public void scepEnrollGetCertAndGetCrl() throws Exception {
    // identity: self-signed RSA certificate, its key and subject are also those of the CSR
    // (RFC 8894 PKCSReq)
    String subject = subject();
    Path identity = newScepIdentity(subject);
    Path csr = file("scep.csr");
    sec("csr-p12", "--p12", identity.toString(), "--password", PWD, "--subject", subject,
        "-c", GatewayTestEnv.USER + ":" + GatewayTestEnv.PASSWORD, "--out", csr.toString());

    Path out = file("scep.der");
    ok("scep-enroll", "--url", scepUrl(), "--ca-cert", caCertFile.toString(),
        "--p12", identity.toString(), "--password", PWD, "--csr", csr.toString(),
        "--out", out.toString());
    X509Cert cert = X509Util.parseCert(out.toFile());
    Assert.assertTrue(X509Util.issues(caCert, cert));
    Assert.assertEquals(certOf(identity).publicKey(), cert.publicKey());

    Path got = file("scep-got.der");
    ok("scep-get-cert", "--url", scepUrl(), "--ca-cert", caCertFile.toString(),
        "--p12", identity.toString(), "--password", PWD,
        "--serial", "0x" + cert.serialNumber().toString(16), "--out", got.toString());
    Assert.assertArrayEquals(cert.getEncoded(), Files.readAllBytes(got));

    caManager.generateCrlOnDemand(CA);
    Path crl = file("scep.crl");
    ok("scep-get-crl", "--url", scepUrl(), "--ca-cert", caCertFile.toString(),
        "--p12", identity.toString(), "--password", PWD, "--cert", out.toString(),
        "--out", crl.toString());
    Assert.assertTrue(Files.size(crl) > 0);

    Path polled = file("scep-poll.der");
    ok("scep-certpoll", "--url", scepUrl(), "--ca-cert", caCertFile.toString(),
        "--p12", identity.toString(), "--password", PWD, "--csr", csr.toString(),
        "--out", polled.toString());
    Assert.assertEquals(cert.publicKey(), X509Util.parseCert(polled.toFile()).publicKey());
  }

  @Test
  public void scepEnrollWithWrongPasswordFails() throws Exception {
    String subject = subject();
    Path identity = newScepIdentity(subject);
    Path csr = file("scep-wrong.csr");
    sec("csr-p12", "--p12", identity.toString(), "--password", PWD, "--subject", subject,
        "-c", GatewayTestEnv.USER + ":wrong", "--out", csr.toString());
    assertFails("server returned 'failure'", "scep-enroll", "--url", scepUrl(),
        "--ca-cert", caCertFile.toString(), "--p12", identity.toString(), "--password", PWD,
        "--csr", csr.toString(), "--out", file("x.der").toString());
  }

  @Test
  public void scepPasswordFromStdin() throws Exception {
    // without --password: the keystore password is read once from the standard input
    Path out = file("scep-ca-stdin.der");
    String subject = subject();
    Path identity = newScepIdentity(subject);
    Path csr = file("scep-stdin.csr");
    sec("csr-p12", "--p12", identity.toString(), "--password", PWD, "--subject", subject,
        "-c", GatewayTestEnv.USER + ":" + GatewayTestEnv.PASSWORD, "--out", csr.toString());
    okIn(PWD + "\n", "scep-enroll", "--url", scepUrl(), "--ca-cert", caCertFile.toString(),
        "--p12", identity.toString(), "--csr", csr.toString(), "--out", out.toString());
    Assert.assertTrue(Files.exists(out));
  }

  // ----- OCSP -----

  @Test
  public void ocspStatusGood() throws Exception {
    X509Cert good = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    Path goodFile = file("good.der");
    Files.write(goodFile, good.getEncoded());

    String out = ok("ocsp-status", "--issuer", caCertFile.toString(), "--url", ocspUrl(),
        "--cert", goodFile.toString());
    Assert.assertTrue(out, out.contains("serial=" + good.serialNumber() + " status=good"));

    // hex serial without prefix
    out = ok("ocsp-status", "--issuer", caCertFile.toString(), "--url", ocspUrl(),
        "--serial", good.serialNumber().toString(16), "--hex");
    Assert.assertTrue(out, out.contains("status=good"));

    // the reason as its name
    X509Cert revoked = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    caManager.revokeCertificate(CA, revoked.serialNumber(), CrlReason.KEY_COMPROMISE, null);
    out = ok("ocsp-status", "--issuer", caCertFile.toString(), "--url", ocspUrl(),
        "--serial", "0x" + revoked.serialNumber().toString(16));
    Assert.assertTrue(out, out.contains("status=revoked reason=keyCompromise"));
  }

  @Test
  public void ocspStatus() throws Exception {
    X509Cert revoked = cmpEnrollP12(newKeystore("P256"), "cr", signerP12Args());
    caManager.revokeCertificate(CA, revoked.serialNumber(), CrlReason.KEY_COMPROMISE, null);

    String out = ok("ocsp-status", "--issuer", caCertFile.toString(), "--url", ocspUrl(),
        "--serial", "0x" + revoked.serialNumber().toString(16), "--nonce", "-v");
    Assert.assertTrue(out, out.contains("status=revoked"));
    Assert.assertTrue(out, out.contains("producedAt="));

    assertFails("neither serial nor cert is set", "ocsp-status",
        "--issuer", caCertFile.toString(), "--url", ocspUrl());
  }

  // ----- helpers -----

  private static String[] signerP12Args() {
    return new String[] {"--signer-p12", requestorP12.toString(), "--signer-password", PWD};
  }

  private static String[] signerPbmArgs() {
    return new String[] {"--signer-keyid", PBM_USER, "--signer-password", PBM_PASSWORD};
  }

  private static X509Cert cmpEnrollP12(Path p12, String reqType, String[] signerArgs)
      throws Exception {
    Path out = file("cmp.der");
    String[] args = {"cmp-enroll-p12", "--ca", CA, "--p12", p12.toString(), "--password", PWD,
        "--subject", subject(), "--profile", PROFILE, "--cmpreq-type", reqType,
        "--out", out.toString()};
    String[] all = new String[args.length + signerArgs.length];
    System.arraycopy(args, 0, all, 0, args.length);
    System.arraycopy(signerArgs, 0, all, args.length, signerArgs.length);
    ok(all);
    X509Cert cert = X509Util.parseCert(out.toFile());
    Assert.assertTrue(X509Util.issues(caCert, cert));
    return cert;
  }

  private static String subject() {
    return "CN=client" + COUNTER.incrementAndGet() + ".example.org,O=myorg,C=DE";
  }

  private static String scepUrl() {
    return scepServer.url() + "scep/pkiclient.exe";
  }

  private static String ocspUrl() {
    return "http://127.0.0.1:" + ocspHttpServer.getAddress().getPort() + "/ocsp";
  }

  private static boolean crlContains(Path crlFile, BigInteger serial) throws Exception {
    CertificateList crl = CertificateList.fromEncoded(Files.readAllBytes(crlFile));
    List<CRLEntry> entries = crl.getRevokedCertificates();
    if (entries != null) {
      for (CRLEntry entry : entries) {
        if (serial.equals(entry.userCertificate())) {
          return true;
        }
      }
    }
    return false;
  }

  private static void addProfile(String name, String file) throws Exception {
    Path dir = null;
    for (Path p = Paths.get("").toAbsolutePath(); p != null; p = p.getParent()) {
      if (Files.isDirectory(p.resolve(SETUP_PROFILES))) {
        dir = p.resolve(SETUP_PROFILES);
        break;
      }
    }
    Assert.assertNotNull(SETUP_PROFILES, dir);
    caManager.addCertprofile(new CertprofileEntry(new NameId(null, name), "xijson",
        Files.readString(dir.resolve("certprofile-" + file + ".json"))));
    caManager.addCertprofileToCa(name, CA);
  }

  /** Issues an RA certificate for the key of the keystore, the keystore is not changed. */
  private static X509Cert issueRaCert(Path p12, String profile) throws Exception {
    X509KeypairWithCert kp;
    try (InputStream in = Files.newInputStream(p12)) {
      kp = X509KeypairWithCert.fromPKCS12Keystore(in, PWD.toCharArray(), null,
          PWD.toCharArray(), (X509Cert) null);
    }
    byte[] csr = new CertificationRequest.CsrBuilder(
        new X500Name("CN=" + profile + "-ra,O=myorg,C=DE"),
        kp.certChain()[0].subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(kp.getKey(), kp.publicKey()).contentSigner()).getEncoded();
    return caManager.generateCertificate(CA, profile, csr, null, null).x509Cert();
  }

  /** PKCS#12 keystore with an RSA key and a self-signed certificate with the subject. */
  private static Path newScepIdentity(String subject) throws Exception {
    X509KeyPairWithSubjectPublicKeyInfo kp = KeyUtil.generateX509KeyPair2(KeySpec.RSA2048);
    X500Name name = new X500Name(subject);
    Instant now = Instant.now();
    Certificate cert = new Certificate.V3CertBuilder(name, BigInteger.ONE,
        now.minusSeconds(60), now.plusSeconds(3600), name, kp.subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(kp.keypair().getPrivate(), kp.keypair().getPublic())
            .contentSigner());
    Pkcs12KeyStore ks = KeyUtil.loadPKCS12KeyStore((byte[]) null, PWD.toCharArray());
    ks.setKeyEntry("main", PrivateKeyInfo.fromEncoded(kp.keypair().getPrivate().getEncoded()),
        cert);
    Path p12 = file("identity.p12");
    try (OutputStream out = Files.newOutputStream(p12)) {
      ks.store(out, PWD.toCharArray());
    }
    return p12;
  }

  private static ConcurrentSigner newSigner(SecurityFactory securityFactory, Path p12)
      throws Exception {
    return securityFactory.createSigner("pkcs12", new SignerConf("password=" + PWD
        + ",algo=" + SIG_ALGO + ",keystore=base64:"
        + Base64.encodeToString(Files.readAllBytes(p12))), (CertVariant) null);
  }

  private static Path newKeystore(String keyspec) throws Exception {
    Path p12 = file("key.p12");
    Files.write(p12, KeyUtil.generateX509KeyPair3(KeySpec.ofKeySpec(keyspec),
        new KeystoreGenerationParameters(PWD.toCharArray())).keystore());
    return p12;
  }

  private static X509Cert certOf(Path p12) throws Exception {
    try (InputStream in = Files.newInputStream(p12)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, PWD.toCharArray(), null,
          PWD.toCharArray(), (X509Cert) null).certChain()[0];
    }
  }

  /** A new file (not existing: an existing file would be confirmed on stdin) in the work dir. */
  private static Path file(String name) {
    return work.resolve(COUNTER.incrementAndGet() + "-" + name);
  }

  /** Runs a command of the security shell and asserts success. */
  private static void sec(String... args) {
    Result r = run(new SecurityShellMain.RootCommand(), null, args);
    Assert.assertEquals(String.join(" ", args) + "\nerr: " + r.err, 0, r.exitCode);
  }

  private static String ok(String... args) {
    return okIn(null, args);
  }

  /** Runs the command with the given standard input, asserts success, returns the output. */
  private static String okIn(String stdin, String... args) {
    Result r = run(new PkiClientShellMain.RootCommand(), stdin, args);
    Assert.assertEquals(String.join(" ", args) + "\nout: " + r.out + "\nerr: " + r.err,
        0, r.exitCode);
    return r.out;
  }

  /** Runs the command and asserts that it fails with the given text in the error output. */
  private static void assertFails(String expectedText, String... args) {
    Result r = run(new PkiClientShellMain.RootCommand(), null, args);
    Assert.assertNotEquals(String.join(" ", args) + "\nout: " + r.out, 0, r.exitCode);
    if (expectedText != null) {
      Assert.assertTrue("expected '" + expectedText + "' in\n" + r.err,
          r.err.contains(expectedText));
    }
  }

  private static Result run(Object rootCommand, String stdin, String... args) {
    InputStream oldIn = System.in;
    PrintStream oldOut = System.out;
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    ByteArrayOutputStream sysOut = new ByteArrayOutputStream();
    try {
      System.setIn(new ByteArrayInputStream(
          (stdin == null ? "" : stdin).getBytes(StandardCharsets.UTF_8)));
      System.setOut(new PrintStream(sysOut, true, StandardCharsets.UTF_8));
      CommandLine cl = new CommandLine(rootCommand);
      cl.setOut(new PrintWriter(out, true));
      cl.setErr(new PrintWriter(err, true));
      int exitCode = cl.execute(args);
      return new Result(exitCode, out + sysOut.toString(StandardCharsets.UTF_8), err.toString());
    } finally {
      System.setIn(oldIn);
      System.setOut(oldOut);
    }
  }

  private static final class Result {

    private final int exitCode;

    private final String out;

    private final String err;

    private Result(int exitCode, String out, String err) {
      this.exitCode = exitCode;
      this.out = out;
      this.err = err;
    }

  }

}
