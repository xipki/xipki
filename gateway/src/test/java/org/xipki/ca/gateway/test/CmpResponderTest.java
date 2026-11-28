// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.cmp.CmpControl;
import org.xipki.ca.gateway.cmp.CmpHttpServlet;
import org.xipki.ca.gateway.cmp.CmpProtocolConf;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.cmp.client.CertIdOrError;
import org.xipki.cmp.client.EnrollCertResult;
import org.xipki.cmp.client.PkiErrorException;
import org.xipki.cmp.client.Requestor;
import org.xipki.cmp.client.internal.CmpClientImpl;
import org.xipki.codec.Base64;
import org.xipki.codec.json.JsonParser;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.auth.SimpleRequestorAuthenticator;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.KemHmacSigner;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

/**
 * The CMP responder of the gateway ({@link CmpResponder}, {@link CmpHttpServlet}) with the CMP
 * client of pki-client ({@link CmpClientImpl}), against the CA of {@link GatewayTestEnv}.
 * Requests and responses are protected by signatures.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpResponderTest {

  private static final String CA = GatewayTestEnv.CA;

  private static final String PROFILE = GatewayTestEnv.PROFILE;

  private static final String SIG_ALGO = "SHA256withECDSA";

  private static final String PBM_USER = "cmp-user";

  private static final String PBM_PASSWORD = "cmp-password";

  private static GatewayTestEnv env;

  private static ServletTestServer server;

  private static CmpClientImpl client;

  private static Requestor.SignatureCmpRequestor requestor;

  private static Requestor.SignatureCmpRequestor unknownRequestor;

  private static X509Cert caCert;

  private static X509Cert responderCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    SecurityFactory securityFactory = env.ca().securities().securityFactory();
    caCert = env.ca().caCert();

    ConcurrentSigner responderSigner = newSigner(securityFactory);
    responderCert = responderSigner.cert().x509Cert();
    ConcurrentSigner requestorSigner = newSigner(securityFactory);
    ConcurrentSigner unknownSigner = newSigner(securityFactory);

    // the requestor is permitted for CMP by its certificate
    Path workDir = env.ca().workDir();
    Path requestorsConf = workDir.resolve("cmp-requestors.json");
    Files.writeString(requestorsConf, "{\"passwords\": [{\"user\": \"" + PBM_USER
        + "\", \"password\": \"" + PBM_PASSWORD + "\",\n"
        + "  \"protocols\": [\"CMP\"], \"permissions\": [\"ALL\"],\n"
        + "  \"caProfiles\": [{\"ca\": \"ALL\", \"profiles\": [\"ALL\"]}]}],\n"
        + "\"certs\": [{\"cert\": {\"binary\": \""
        + Base64.encodeToString(requestorSigner.cert().x509Cert().getEncoded()) + "\"},\n"
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
    server = new ServletTestServer("/cmp", new CmpHttpServlet(false, null, responder)::service,
        null);

    // with an empty ssl block: without it the client cannot be initialized (C1)
    client = newClient(clientConf(responderCert, ", \"ssl\": {}"));

    requestor = new Requestor.SignatureCmpRequestor(requestorSigner);
    unknownRequestor = new Requestor.SignatureCmpRequestor(unknownSigner);
  }

  @AfterClass
  public static void shutdown() {
    if (client != null) {
      client.close();
    }
    if (server != null) {
      server.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void enrollWithCsr() throws Exception {
    X509Cert cert = enroll("cmp1.example.org");
    cert.verify(caCert.publicKey());
    Assert.assertEquals(caCert.subject(), cert.issuer());
    Assert.assertNotNull(env.ca().caManager().getCert(CA, cert.serialNumber()));
  }

  @Test
  public void revokeAndUnsuspend() throws Exception {
    BigInteger serial = enroll("cmp-revoke.example.org").serialNumber();

    CertIdOrError result = client.revokeCert(CA, requestor, caCert, serial,
        CrlReason.CERTIFICATE_HOLD.code(), null, null);
    Assert.assertNull("revocation error", result.error());
    Assert.assertTrue(env.ca().caManager().getCert(CA, serial).isRevoked());

    result = client.unsuspendCert(CA, requestor, caCert, serial, null);
    Assert.assertNull("unsuspend error", result.error());
    Assert.assertFalse(env.ca().caManager().getCert(CA, serial).isRevoked());
  }

  @Test
  public void enrollWithPasswordBasedMac() throws Exception {
    EnrollCertResult result = client.enrollCert(CA, pbmRequestor(PBM_PASSWORD),
        csr("cmp-pbm.example.org"), PROFILE, null, null, null);
    EnrollCertResult.CertifiedKeyPairOrError certOrError =
        result.getCertOrError(result.allIds().iterator().next());
    Assert.assertNull("error", certOrError.error());
    certOrError.certificate().verify(caCert.publicKey());
  }

  @Test
  public void wrongPasswordIsRejected() {
    Assert.assertThrows(Exception.class, () -> client.enrollCert(CA, pbmRequestor("wrong"),
        csr("cmp-pbm-wrong.example.org"), PROFILE, null, null, null));
  }

  @Test
  public void caCertAndCrl() throws Exception {
    Assert.assertEquals(caCert, client.caCert(CA, null));
    env.ca().caManager().generateCrlOnDemand(CA);
    CertificateList crl = client.downloadCrl(CA, null);
    Assert.assertNotNull(crl);
  }

  @Test
  public void unknownRequestorIsRejected() throws Exception {
    Assert.assertThrows(PkiErrorException.class, () -> client.enrollCert(CA, unknownRequestor,
        csr("unknown.example.org"), PROFILE, null, null, null));
  }

  @Test
  public void unknownCaIsRejected() {
    Assert.assertThrows(Exception.class, () -> client.enrollCert("no-such-ca", requestor,
        csr("x.example.org"), PROFILE, null, null, null));
  }

  @Test
  public void clientWithoutSslConf() throws Exception {
    CmpClientImpl noSslClient = newClient(clientConf(responderCert, ""));
    try {
      Assert.assertEquals(caCert, noSslClient.caCert(CA, null));
    } finally {
      noSslClient.close();
    }
  }

  /**
   * KEM-based POP via CMP: the KEM encap key from the gateway (genm), then enrollment (p10cr)
   * with the CSR whose POP is the MAC with the decapsulated key.
   */
  @Test
  public void enrollWithKemPop() throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(KeySpec.MLKEM768);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.fromPublicKey(kp.getPublic());
    KemEncapKey encapKey = client.generateKemEncapKey(CA, requestor, spki, null);
    byte[] macKey = KemUtil.mlkemDecryptSecret(kp.getPrivate(),
        encapKey.encapulation());
    CertificationRequest csr = new CertificationRequest.CsrBuilder(
        new X500Name("CN=cmp-kempop.example.org,O=myorg,C=DE"), spki)
        .build(new KemHmacSigner(encapKey.id(),
            new SecretKeySpec(macKey, "HMAC-SHA256")).contentSigner());

    EnrollCertResult result = client.enrollCert(CA, requestor, csr,
        GatewayTestEnv.PROFILE_KEX, null, null, null);
    EnrollCertResult.CertifiedKeyPairOrError certOrError =
        result.getCertOrError(result.allIds().iterator().next());
    Assert.assertNull("error", certOrError.error());
    Assert.assertEquals(spki, certOrError.certificate().subjectPublicKeyInfo());
  }

  /** The HTTP errors of the CMP servlet ({@code CmpHttpServlet}). */
  @Test
  public void httpErrors() throws Exception {
    byte[] garbage = {0x30, 0x03, 0x02, 0x01, 0x01};
    String ct = "application/pkixcmp";
    Assert.assertEquals(405, httpStatus("GET", CA, null, null));
    Assert.assertEquals(415, httpStatus("POST", CA, "application/octet-stream", garbage));
    Assert.assertEquals(415, httpStatus("POST", CA, null, garbage));
    // no CA in the path
    Assert.assertEquals(404, httpStatus("POST", "", ct, garbage));
    // not a PKIMessage
    Assert.assertEquals(400, httpStatus("POST", CA, ct, garbage));
  }

  private static int httpStatus(String method, String path, String contentType, byte[] body)
      throws Exception {
    java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
        java.net.URI.create(server.url() + path).toURL().openConnection();
    conn.setRequestMethod(method);
    if (contentType != null) {
      conn.setRequestProperty("Content-Type", contentType);
    }
    if (body != null) {
      conn.setDoOutput(true);
      try (java.io.OutputStream out = conn.getOutputStream()) {
        out.write(body);
      }
    }
    try {
      return conn.getResponseCode();
    } finally {
      conn.disconnect();
    }
  }

  private static String clientConf(X509Cert responderCert, String extra) throws Exception {
    return "{\"sendRequestorCert\": true, \"responder\": {"
        + "\"url\": \"" + server.url() + "\", \"signature\": {"
        + "\"cert\": {\"binary\": \"" + Base64.encodeToString(responderCert.getEncoded())
        + "\"}, \"signatureAlgos\": [\"" + SIG_ALGO + "\"]},"
        + " \"pbmMac\": {\"owfAlgos\": [\"SHA256\"], \"macAlgos\": [\"HMAC-SHA256\"]}}"
        + extra + "}";
  }

  private static CmpClientImpl newClient(String conf) throws Exception {
    Path file = Files.createTempFile(env.ca().workDir(), "cmp-client", ".json");
    Files.writeString(file, conf);
    CmpClientImpl ret = new CmpClientImpl();
    ret.setSecurityFactory(env.ca().securities().securityFactory());
    ret.setConfFile(file.toString());
    ret.init();
    return ret;
  }

  private static X509Cert enroll(String commonName) throws Exception {
    EnrollCertResult result = client.enrollCert(CA, requestor, csr(commonName), PROFILE,
        null, null, null);
    String id = result.allIds().iterator().next();
    EnrollCertResult.CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
    Assert.assertNull("error", certOrError.error());
    return certOrError.certificate();
  }

  private static Requestor pbmRequestor(String password) {
    return new Requestor.PbmMacCmpRequestor(password.toCharArray(),
        PBM_USER.getBytes(StandardCharsets.UTF_8), HashAlgo.SHA256, 10240,
        SignAlgo.HMAC_SHA256);
  }

  private static CertificationRequest csr(String commonName) throws Exception {
    return X509Util.parseCsr(GatewayTestEnv.newCsr("CN=" + commonName + ",O=myorg,C=DE"));
  }

  private static ConcurrentSigner newSigner(SecurityFactory securityFactory) throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    SignerConf conf = new SignerConf("password=CHANGEIT,algo=" + SIG_ALGO
        + ",keystore=base64:" + Base64.encodeToString(keystore));
    return securityFactory.createSigner("pkcs12", conf, (CertVariant) null);
  }

}
