// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x509.CRLEntry;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.servlet.CaMgmtTestServer;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.ca.mgmt.shell.CaMgmtShellMain;
import org.xipki.shell.security.SecurityShellMain;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipInputStream;

/**
 * The commands of the CA management shell, executed as in the CLI (picocli, root command of the
 * module), with the management client configured in {@code xipki/etc/ca-mgmt-client.json} of a
 * temporary shell home, against the management servlet of a CA system on in-memory H2
 * databases ({@link CaH2TestEnv}, CA {@code rootca1}, profiles {@code rootca} and
 * {@code tls-ec}). The results are checked on the server side.
 *
 * @author Lijun Liao (xipki)
 */
public class CaMgmtShellH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static final String PROFILE = CaH2TestEnv.PROFILE_TLS;

  private static final String PWD = "CHANGEIT";

  private static final AtomicInteger COUNTER = new AtomicInteger();

  private static CaH2TestEnv env;

  private static CaManagerImpl server;

  private static CaMgmtTestServer httpServer;

  private static Path work;

  @BeforeClass
  public static void init() throws Exception {
    Path home = Files.createTempDirectory("xipki-ca-mgmt-shell");
    work = Files.createDirectories(home.resolve("work"));

    env = new CaH2TestEnv(true);
    server = env.caManager();
    X509Cert mgmtCert = newKeystoreCert();
    httpServer = new CaMgmtTestServer(server, mgmtCert, mgmtCert);

    Path etc = Files.createDirectories(home.resolve("xipki/etc"));
    Files.writeString(etc.resolve("ca-mgmt-client.json"),
        "{\"serverUrl\": \"" + httpServer.url() + "\", \"useSslConf\": false}");
    // for the commands of the security shell (CSR)
    Files.writeString(etc.resolve("security.json"), "{}");
    System.setProperty("org.xipki.shell.home", home.toString());
  }

  @AfterClass
  public static void shutdown() {
    System.clearProperty("org.xipki.shell.home");
    if (httpServer != null) {
      httpServer.close();
    }
    if (env != null) {
      env.close();
    }
  }

  // ----- system -----

  @Test
  public void systemStatusAndCaInfo() throws Exception {
    Assert.assertTrue(ok("system-status").contains("STARTED_AS_MASTER"));

    String out = ok("ca-info");
    Assert.assertTrue(out, out.contains("successful CAs:\n  " + CA));

    out = ok("ca-info", CA);
    Assert.assertTrue(out, out.contains("started:              true"));
    Assert.assertTrue(out, out.contains(PROFILE));

    assertFails("Unknown CA no-such-ca", "ca-info", "no-such-ca");
  }

  @Test
  public void caCertAndCaCerts() throws Exception {
    Path der = file("ca.der");
    ok("cacert", CA, "--out", der.toString());
    Assert.assertArrayEquals(env.caCert().getEncoded(), Files.readAllBytes(der));

    Path pem = file("ca.pem");
    ok("cacert", CA, "--outform", "pem", "--out", pem.toString());
    Assert.assertEquals(env.caCert(), X509Util.parseCert(pem.toFile()));

    Path chain = file("chain.pem");
    ok("cacerts", CA, "--out", chain.toString());
    Assert.assertEquals(env.caCert(), X509Util.parseCert(chain.toFile()));
  }

  @Test
  public void restartAndNotify() throws Exception {
    String out = ok("restart");
    Assert.assertTrue(out, out.contains("restarted CA system"));
    Assert.assertTrue(out, out.contains("successful CAs:\n    " + CA));
    Assert.assertTrue(ok("restart-ca", CA).contains("restarted CA " + CA));
    Assert.assertTrue(ok("notify-change").contains("notified"));
    Assert.assertTrue(server.getSuccessfulCaNames().contains(CA));
  }

  @Test
  public void caAlias() throws Exception {
    String alias = "alias-" + COUNTER.incrementAndGet();
    ok("caalias-add", "--ca", CA, "--alias", alias);
    Assert.assertEquals(CA, server.getCaNameForAlias(alias));
    Assert.assertTrue(ok("caalias-info").contains(alias));
    Assert.assertTrue(ok("caalias-info", alias).contains(CA));

    ok("caalias-rm", alias, "-f");
    Assert.assertNull(server.getCaNameForAlias(alias));
    assertFails("could not find CA alias", "caalias-info", alias);
  }

  @Test
  public void dbSchema() throws Exception {
    String name = "TEST_KEY_" + COUNTER.incrementAndGet();
    ok("dbschema-add", "--name", name, "--value", "v1");
    Assert.assertTrue(ok("dbschema-info").contains(name + ": v1"));
    ok("dbschema-up", "--name", name, "--value", "v2");
    Assert.assertEquals("v2", server.getDbSchemas().get(name));
    ok("dbschema-rm", "--name", name);
    Assert.assertFalse(server.getDbSchemas().containsKey(name));
  }

  // ----- profiles, requestors, signers, publishers, keypair generations -----

  @Test
  public void profiles() throws Exception {
    Path confFile = file("profile.json");
    ok("profile-export", "--name", PROFILE, "--out", confFile.toString());
    Assert.assertEquals(server.getCertprofile(PROFILE).conf(), Files.readString(confFile));

    String name = "profile-" + COUNTER.incrementAndGet();
    ok("profile-add", "--name", name, "--conf-file", confFile.toString());
    Assert.assertNotNull(server.getCertprofile(name));
    Assert.assertTrue(ok("profile-info").contains(name));
    Assert.assertTrue(ok("profile-info", name).contains("xijson"));
    Assert.assertFalse(ok("simple-profile-info", name).isBlank());

    ok("caprofile-add", "--ca", CA, "--profile", name + ":" + name + "-a1," + name + "-a2");
    String out = ok("caprofile-info", "--ca", CA);
    Assert.assertTrue(out, out.contains(name + " (aliases " + name + "-a1, " + name + "-a2)"));
    ok("caprofile-rm", "--ca", CA, "--profile", name, "-f");
    Assert.assertFalse(ok("caprofile-info", "--ca", CA).contains(name));

    assertFails("nothing to update", "profile-up", "--name", name);

    ok("profile-rm", name, "-f");
    Assert.assertNull(server.getCertprofile(name));
    assertFails("Unknown Certprofile " + name, "profile-info", name);
  }

  @Test
  public void requestors() throws Exception {
    Path cert1 = writeCert(newKeystoreCert());
    String name = "requestor-" + COUNTER.incrementAndGet();

    ok("requestor-add", "--name", name, "--cert", cert1.toString());
    Assert.assertNotNull(server.getRequestor(name));
    Assert.assertTrue(ok("requestor-info").contains(name));
    Assert.assertFalse(ok("requestor-info", name, "-v").isBlank());

    ok("careq-add", "--ca", CA, "--requestor", name, "--permission", "enroll_cert",
        "--permission", "revoke_cert", "--profile", PROFILE);
    String out = ok("careq-info", "--ca", CA);
    Assert.assertTrue(out, out.contains(name));
    ok("careq-rm", "--ca", CA, "--requestor", name, "-f");
    Assert.assertFalse(ok("careq-info", "--ca", CA).contains(name));

    ok("requestor-rm", name, "-f");
    Assert.assertNull(server.getRequestor(name));
  }

  @Test
  public void signers() throws Exception {
    Path p12 = newKeystore();
    String name = "signer-" + COUNTER.incrementAndGet();
    ok("signer-add", "--name", name, "--type", "pkcs12", "--conf", signerConf(p12));
    // the keystore file is embedded in the configuration
    String conf = server.getSigner(name).conf();
    Assert.assertTrue(conf, conf.contains("keystore=base64:"));
    Assert.assertTrue(ok("signer-info").contains(name));
    Assert.assertTrue(ok("signer-info", name).contains(name));

    ok("signer-rm", name, "-f");
    Assert.assertNull(server.getSigner(name));
  }

  @Test
  public void publishers() throws Exception {
    String name = "publisher-" + COUNTER.incrementAndGet();
    ok("publisher-add", "--name", name, "--type", "ocsp",
        "--conf", "datasource=ocsp,publish.goodcerts=true");
    Assert.assertNotNull(server.getPublisher(name));
    Assert.assertTrue(ok("publisher-info").contains(name));
    Assert.assertTrue(ok("publisher-info", name).contains("ocsp"));

    Path confFile = file("publisher.conf");
    ok("publisher-export", "--name", name, "--out", confFile.toString());
    Assert.assertEquals(server.getPublisher(name).conf(), Files.readString(confFile));

    ok("capub-add", "--ca", CA, "--publisher", name);
    Assert.assertTrue(ok("capub-info", "--ca", CA).contains(name));
    Assert.assertTrue(ok("republish", "--ca", CA, "--publisher", name)
        .contains("republished certificates"));
    ok("capub-rm", "--ca", CA, "--publisher", name, "-f");
    Assert.assertFalse(server.getPublisherNamesForCa(CA).contains(name));

    ok("publisher-rm", name, "-f");
    Assert.assertNull(server.getPublisher(name));
  }

  @Test
  public void keypairGens() throws Exception {
    String name = "kg-" + COUNTER.incrementAndGet();
    ok("keypairgen-add", "--name", name, "--type", "software");
    Assert.assertNotNull(server.getKeypairGen(name));
    Assert.assertTrue(ok("keypairgen-info").contains(name));
    Assert.assertTrue(ok("keypairgen-info", name).contains("software"));
    ok("keypairgen-rm", name, "-f");
    Assert.assertNull(server.getKeypairGen(name));
  }

  // ----- certificates and CRLs -----

  @Test
  public void enrollRevokeAndCrl() throws Exception {
    Path certFile = file("ee.der");
    ok("enroll-cert", "--ca", CA, "--profile", PROFILE,
        "--subject", "CN=ee" + COUNTER.incrementAndGet() + ".example.org,O=myorg,C=DE",
        "--key-password", PWD, "--out", certFile.toString());
    X509Cert cert = X509Util.parseCert(certFile.toFile());
    Assert.assertTrue(X509Util.issues(env.caCert(), cert));
    // PKCS#12 keystore with the generated key next to the certificate
    Path p12 = Path.of(certFile.toString().replace(".der", ".p12"));
    Assert.assertEquals(cert, certOf(p12));

    String serial = "0x" + cert.serialNumber().toString(16);
    String out = ok("cert-status", "--ca", CA, "--serial", serial);
    Assert.assertTrue(out, out.contains("status: good"));
    Assert.assertTrue(out, out.contains("certificate profile: " + PROFILE));

    Path got = file("got.der");
    ok("get-cert", "--ca", CA, "--serial", serial, "--out", got.toString());
    Assert.assertArrayEquals(cert.getEncoded(), Files.readAllBytes(got));

    out = ok("list-cert", "--ca", CA);
    Assert.assertTrue(out, out.contains(cert.serialNumber().toString(16)));

    // certificateHold, unsuspend, keyCompromise
    ok("revoke-cert", "--ca", CA, "--cert", certFile.toString(), "--reason", "certificateHold");
    Assert.assertTrue(ok("cert-status", "--ca", CA, "--serial", serial).contains("revoked"));
    ok("unsuspend-cert", "--ca", CA, "--serial", serial);
    Assert.assertTrue(ok("cert-status", "--ca", CA, "--serial", serial)
        .contains("status: good"));
    ok("revoke-cert", "--ca", CA, "--serial", serial, "-r", "keyCompromise");
    Assert.assertEquals(CrlReason.KEY_COMPROMISE,
        server.getCert(CA, cert.serialNumber()).revInfo().reason());

    Path crlFile = file("ca.crl");
    ok("gen-crl", "--ca", CA, "--out", crlFile.toString());
    Assert.assertTrue(crlContains(crlFile, cert.serialNumber()));
    Path currentCrl = file("current.crl");
    ok("get-crl", "--ca", CA, "--out", currentCrl.toString());
    Assert.assertArrayEquals(Files.readAllBytes(crlFile), Files.readAllBytes(currentCrl));

    ok("rm-cert", "--ca", CA, "--serial", serial, "-f");
    Assert.assertTrue(ok("cert-status", "--ca", CA, "--serial", serial)
        .contains("certificate unknown"));

    assertFails("is not permitted", "revoke-cert", "--ca", CA, "--serial", "0x1",
        "--reason", "removeFromCRL");
    assertFails("neither serialNumber nor certFile", "cert-status", "--ca", CA);
  }

  @Test
  public void enrollWithCsr() throws Exception {
    Path p12 = newKeystore();
    Path csr = file("ee.csr");
    String subject = "CN=csr" + COUNTER.incrementAndGet() + ".example.org,O=myorg,C=DE";
    // CSR with the command of the security shell
    Result r = run(new SecurityShellMain.RootCommand(), null, "csr-p12", "--p12", p12.toString(),
        "--password", PWD, "--subject", subject, "--out", csr.toString());
    Assert.assertEquals(r.err, 0, r.exitCode);

    Path certFile = file("csr-ee.pem");
    ok("enroll-cert", "--ca", CA, "--profile", PROFILE, "--csr", csr.toString(),
        "--outform", "pem", "--out", certFile.toString());
    X509Cert cert = X509Util.parseCert(certFile.toFile());
    Assert.assertEquals(certOf(p12).publicKey(), cert.publicKey());

    assertFails("Exactly one of subject or CSR", "enroll-cert", "--ca", CA,
        "--profile", PROFILE, "--out", file("x.der").toString());
  }

  @Test
  public void enrollWithPemKey() throws Exception {
    // unencrypted PEM key (password NONE)
    Path certFile = file("pem-ee.der");
    ok("enroll-cert", "--ca", CA, "--profile", PROFILE,
        "--subject", "CN=pem" + COUNTER.incrementAndGet() + ".example.org,O=myorg,C=DE",
        "--key-outform", "pem", "--key-password", "NONE", "--out", certFile.toString());
    Path keyFile = Path.of(certFile.toString().replace(".der", "-key.pem"));
    Assert.assertTrue(Files.readString(keyFile).startsWith("-----BEGIN PRIVATE KEY-----"));

    // encrypted PEM key
    Path certFile2 = file("pem-ee2.der");
    ok("enroll-cert", "--ca", CA, "--profile", PROFILE,
        "--subject", "CN=pem" + COUNTER.incrementAndGet() + ".example.org,O=myorg,C=DE",
        "--key-outform", "pem", "--key-password", PWD, "--out", certFile2.toString());
    Path keyFile2 = Path.of(certFile2.toString().replace(".der", "-key.pem"));
    Assert.assertTrue(Files.readString(keyFile2)
        .startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));

    assertFails("Password NONE is not allowed", "enroll-cert", "--ca", CA, "--profile", PROFILE,
        "--subject", "CN=x.example.org,O=myorg,C=DE", "--key-password", "NONE",
        "--out", file("y.der").toString());
  }

  @Test
  public void enrollKeyFileNextToCertificate() throws Exception {
    // the keystore is saved next to the certificate: <out without extension>.p12
    Path dir = Files.createDirectories(file("dir.with.dot"));
    Path certFile = dir.resolve("cert");
    ok("enroll-cert", "--ca", CA, "--profile", PROFILE,
        "--subject", "CN=noext" + COUNTER.incrementAndGet() + ".example.org,O=myorg,C=DE",
        "--key-password", PWD, "--out", certFile.toString());
    Assert.assertTrue(Files.exists(certFile));
    Assert.assertTrue("keystore cert.p12 in " + dir, Files.exists(dir.resolve("cert.p12")));
  }

  @Test
  public void listCertWithDate() throws Exception {
    // --valid-from / --valid-to: yyyyMMdd or yyyyMMddHHmmss
    ok("list-cert", "--ca", CA, "--valid-from", "20200101000000");
    ok("list-cert", "--ca", CA, "--valid-from", "20200101");
  }

  @Test
  public void certStatistics() throws Exception {
    String out = ok("cert-statistics");
    Assert.assertTrue(out, out.trim().startsWith("{"));
    assertFails("from and to shall be both present", "cert-statistics", "--from", "202601");
  }

  // ----- CA lifecycle -----

  @Test
  public void genRootcaRevokeAndRemove() throws Exception {
    String name = "ca-" + COUNTER.incrementAndGet();
    Path p12 = newKeystore();
    Path caCertFile = genRootca(name, p12);
    CaEntry ca = server.getCa(name);
    Assert.assertNotNull(name, ca);
    Assert.assertEquals(ca.cert(), CertVariant.ofX509(X509Util.parseCert(caCertFile.toFile())));
    Assert.assertTrue(ok("ca-info", name).contains(name));
    Assert.assertEquals(List.of("http://ocsp.example.org"), ca.base().caUris().ocspUris());

    ok("ca-revoke", name, "--reason", "keyCompromise");
    Assert.assertNotNull(server.getCa(name).base().revocationInfo());
    ok("ca-unrevoke", name);
    Assert.assertNull(server.getCa(name).base().revocationInfo());

    ok("ca-rm", name, "-f");
    Assert.assertNull(server.getCa(name));

    // ca-add with the certificate generated before
    String name2 = "ca-" + COUNTER.incrementAndGet();
    ok("ca-add", "--name", name2, "--permission", "all", "--next-crl-no", "1",
        "--max-validity", "10y", "--signer-type", "pkcs12",
        "--signer-conf", signerConf(p12), "--cert", caCertFile.toString());
    Assert.assertEquals(CertVariant.ofX509(X509Util.parseCert(caCertFile.toFile())),
        server.getCa(name2).cert());
    ok("ca-rm", name2, "-f");

    assertFails("invalid sn-len", "ca-add", "--name", "x", "--permission", "all",
        "--next-crl-no", "1", "--max-validity", "10y", "--signer-type", "pkcs12",
        "--signer-conf", "password=" + PWD, "--sn-len", "100");
  }

  @Test
  public void updateCommands() throws Exception {
    // more updates than connections in the pool of the CA configuration database (5 in the
    // test): each update returns its connection (M1)
    String profile = "up-profile-" + COUNTER.incrementAndGet();
    Path profileConf = file("up-profile.json");
    ok("profile-export", "--name", PROFILE, "--out", profileConf.toString());
    ok("profile-add", "--name", profile, "--conf-file", profileConf.toString());
    ok("profile-up", "--name", profile, "--conf-file", profileConf.toString());

    String requestor = "up-requestor-" + COUNTER.incrementAndGet();
    ok("requestor-add", "--name", requestor, "--cert", writeCert(newKeystoreCert()).toString());
    ok("requestor-up", "--name", requestor, "--cert", writeCert(newKeystoreCert()).toString());

    Path p12 = newKeystore();
    String signer = "up-signer-" + COUNTER.incrementAndGet();
    ok("signer-add", "--name", signer, "--type", "pkcs12", "--conf", signerConf(p12));
    ok("signer-up", "--name", signer, "--cert", writeCert(certOf(p12)).toString());
    Assert.assertNotNull(server.getSigner(signer).base64Cert());

    String publisher = "up-publisher-" + COUNTER.incrementAndGet();
    ok("publisher-add", "--name", publisher, "--type", "ocsp",
        "--conf", "datasource=ocsp,publish.goodcerts=true");
    ok("publisher-up", "--name", publisher, "--conf",
        "datasource=ocsp,publish.goodcerts=false");
    Assert.assertTrue(server.getPublisher(publisher).conf().contains("publish.goodcerts=false"));

    String kg = "up-kg-" + COUNTER.incrementAndGet();
    ok("keypairgen-add", "--name", kg, "--type", "software");
    ok("keypairgen-up", "--name", kg, "--conf", "keyspecs=P256");

    String ca = "up-ca-" + COUNTER.incrementAndGet();
    genRootca(ca, newKeystore());
    // ca-up without URIs keeps the URIs
    ok("ca-up", ca, "--max-validity", "5y");
    CaEntry entry = server.getCa(ca);
    Assert.assertEquals("5y", entry.base().maxValidity().toString());
    Assert.assertEquals(List.of("http://ocsp.example.org"), entry.base().caUris().ocspUris());
    Assert.assertEquals(List.of("http://crl.example.org"), entry.base().caUris().crlUris());

    ok("ca-up", ca, "--status", "inactive");
    Assert.assertEquals(CaStatus.inactive, server.getCa(ca).base().status());
  }

  @Test
  public void caUpRemovesUris() throws Exception {
    String ca = "up-ca-" + COUNTER.incrementAndGet();
    genRootca(ca, newKeystore());
    // ca-up with 'null' removes the URIs
    ok("ca-up", ca, "--ocsp-uri", "null");
    Assert.assertTrue(isEmpty(server.getCa(ca).base().caUris().ocspUris()));
    Assert.assertEquals(List.of("http://crl.example.org"),
        server.getCa(ca).base().caUris().crlUris());
  }

  // ----- configuration -----

  @Test
  public void exportConf() throws Exception {
    Path zip = file("conf.zip");
    ok("export-conf", "--conf-file", zip.toString(), "--ca", CA);
    List<String> entries = new ArrayList<>();
    try (ZipInputStream in = new ZipInputStream(Files.newInputStream(zip))) {
      for (var e = in.getNextEntry(); e != null; e = in.getNextEntry()) {
        entries.add(e.getName());
      }
    }
    Assert.assertFalse(entries.toString(), entries.isEmpty());
  }

  // ----- databases -----

  @Test
  public void exportImportAndDiffDigest() throws Exception {
    Path exportDir = file("export");
    ok("export-ca", "--caconf-db-conf", env.caconfDbConf().toString(),
        "--db-conf", env.caDbConf().toString(), "--out-dir", exportDir.toString(),
        "--password", PWD);

    Path caconf2 = env.newDatabase("caconf-import", true);
    Path ca2 = env.newDatabase("ca-import", false);
    ok("import-ca", "--caconf-db-conf", caconf2.toString(), "--db-conf", ca2.toString(),
        "--in-dir", exportDir.toString(), "--password", PWD);

    Path reportDir = file("diff-report");
    ok("diff-digest", "--ref-db", env.caDbConf().toString(), "--target", ca2.toString(),
        "--report-dir", reportDir.toString());
    Assert.assertTrue(Files.isDirectory(reportDir));
  }

  @Test
  public void sqlScript() throws Exception {
    Path db = env.newDatabase("sql-test", false);
    Path script = file("test.sql");
    Files.writeString(script, "CREATE TABLE SHELL_TEST (ID INT);\n");
    String out = ok("sql", "--db-conf", db.toString(), script.toString(), "-f");
    Assert.assertTrue(out, out.contains("End executing script"));
  }

  // ----- helpers -----

  private static String signerConf(Path p12) {
    return "password=" + PWD + ",keystore=file:" + p12 + ",algo=SHA256withECDSA";
  }

  /** Generates a root CA with OCSP and CRL URIs, returns the file of the CA certificate. */
  private static Path genRootca(String name, Path p12) {
    Path caCertFile = file(name + ".der");
    ok("gen-rootca", "--name", name, "--subject", "CN=" + name + ",O=myorg,C=DE",
        "--profile", "rootca", "--permission", "all", "--next-crl-no", "1",
        "--max-validity", "10y", "--signer-type", "pkcs12", "--signer-conf", signerConf(p12),
        "--ocsp-uri", "http://ocsp.example.org", "--crl-uri", "http://crl.example.org",
        "--out", caCertFile.toString());
    return caCertFile;
  }

  private static boolean isEmpty(List<?> list) {
    return list == null || list.isEmpty();
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

  private static Path newKeystore() throws Exception {
    Path p12 = file("key.p12");
    Files.write(p12, KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(PWD.toCharArray())).keystore());
    return p12;
  }

  private static X509Cert newKeystoreCert() throws Exception {
    return certOf(newKeystore());
  }

  private static X509Cert certOf(Path p12) throws Exception {
    try (InputStream in = Files.newInputStream(p12)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, PWD.toCharArray(), null,
          PWD.toCharArray(), (X509Cert) null).certChain()[0];
    }
  }

  private static Path writeCert(X509Cert cert) throws Exception {
    Path file = file("cert.der");
    Files.write(file, cert.getEncoded());
    return file;
  }

  /** A new file (not existing: an existing file would be confirmed on stdin) in the work dir. */
  private static Path file(String name) {
    return work.resolve(COUNTER.incrementAndGet() + "-" + name);
  }

  /** Runs the command, asserts success and returns the output. */
  private static String ok(String... args) {
    Result r = run(new CaMgmtShellMain.RootCommand(), null, args);
    Assert.assertEquals(String.join(" ", args) + "\nout: " + r.out + "\nerr: " + r.err,
        0, r.exitCode);
    return r.out;
  }

  /** Runs the command and asserts that it fails with the given text in the error output. */
  private static void assertFails(String expectedText, String... args) {
    Result r = run(new CaMgmtShellMain.RootCommand(), null, args);
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
