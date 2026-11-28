// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.servlet.CaMgmtTestServer;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.pkix.ca.CaUris;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.shell.security.SecurityShellMain;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.misc.NameId;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The commands of the QA shell, executed as in the CLI (picocli, root command of the module):
 * the checks of the CA configuration ({@code *-check}, via the management client configured in
 * {@code xipki/etc/ca-mgmt-client.json} of a temporary shell home), the negative wrappers
 * ({@code neg-*}), the certificate check ({@code init-caqa}, {@code check-cert} with
 * {@code xipki/ca-qa/qa-certcheck-conf.json}), {@code fill-keypool} and the speed tests of
 * PKCS#12 keys. The CA system runs on in-memory H2 databases ({@link CaH2TestEnv}) behind the
 * management servlet ({@link CaMgmtTestServer}).
 *
 * @author Lijun Liao (xipki)
 */
public class QaShellH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static final String PROFILE = CaH2TestEnv.PROFILE_TLS;

  private static final String PWD = "CHANGEIT";

  private static final AtomicInteger COUNTER = new AtomicInteger();

  private static CaH2TestEnv env;

  private static CaManagerImpl server;

  private static CaMgmtTestServer httpServer;

  private static Path work;

  private static Path qaConf;

  private static Path caCertFile;

  @BeforeClass
  public static void init() throws Exception {
    Path home = Files.createTempDirectory("xipki-qa-shell");
    work = Files.createDirectories(home.resolve("work"));

    env = new CaH2TestEnv("ocsp", "keypool");
    server = env.caManager();
    X509Cert mgmtCert = certOf(newKeystore());
    httpServer = new CaMgmtTestServer(server, mgmtCert, mgmtCert);

    caCertFile = file("ca.der");
    Files.write(caCertFile, env.caCert().getEncoded());

    Path etc = Files.createDirectories(home.resolve("xipki/etc"));
    Files.writeString(etc.resolve("ca-mgmt-client.json"),
        "{\"serverUrl\": \"" + httpServer.url() + "\", \"useSslConf\": false}");
    Files.writeString(etc.resolve("security.json"), "{}");

    // QA configuration: the CA as issuer, the profiles rootca and tls-ec
    Path rootcaProfile = file("rootca.json");
    Files.writeString(rootcaProfile, server.getCertprofile("rootca").conf());
    Path tlsProfile = file("tls.json");
    Files.writeString(tlsProfile, server.getCertprofile(PROFILE).conf());
    qaConf = Files.createDirectories(home.resolve("xipki/ca-qa"))
        .resolve("qa-certcheck-conf.json");
    Files.writeString(qaConf, qaConfJson(rootcaProfile, tlsProfile));

    System.setProperty("org.xipki.shell.home", home.toString());
  }

  private static String qaConfJson(Path rootcaProfile, Path tlsProfile) throws Exception {
    CaUris uris = server.getCa(CA).base().caUris();
    return "{\"issuers\": [{\"name\": \"rootca\", \"cert\": {\"file\": \"" + path(caCertFile)
        + "\"}, \"validityMode\": \"cutoff\", \"caIssuerUrls\": " + jsonList(uris.cacertUris())
        + ", \"ocspUrls\": " + jsonList(uris.ocspUris())
        + ", \"crlUrls\": " + jsonList(uris.crlUris())
        + ", \"deltaCrlUrls\": " + jsonList(uris.deltaCrlUris()) + "}],"
        + " \"certprofiles\": [{\"name\": \"rootca\", \"file\": \"" + path(rootcaProfile)
        + "\"}, {\"name\": \"" + PROFILE + "\", \"file\": \"" + path(tlsProfile) + "\"}]}";
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

  // ----- certificate check -----

  @Test
  public void initCaQaAndCheckCert() throws Exception {
    Assert.assertTrue(ok("init-caqa").contains("initialized successfully"));

    Path p12 = newKeystore();
    Path csr = file("qa.csr");
    String subject = "CN=qa" + COUNTER.incrementAndGet() + ".example.org,O=myorg,C=DE";
    Result r = run(new SecurityShellMain.RootCommand(), "csr-p12", "--p12", p12.toString(),
        "--password", PWD, "--subject", subject, "--out", csr.toString());
    Assert.assertEquals(r.err, 0, r.exitCode);
    Path cert = file("qa.der");
    Files.write(cert, server.generateCertificate(CA, PROFILE, Files.readAllBytes(csr), null, null)
        .getEncoded());

    String out = ok("check-cert", "--cert", cert.toString(), "--csr", csr.toString(),
        "--profile", PROFILE, "--issuer", "rootca");
    Assert.assertTrue(out, out.contains("certificate is valid"));

    // against another profile: invalid
    assertFails("certificate is invalid", "check-cert", "--cert", cert.toString(),
        "--csr", csr.toString(), "--profile", "rootca");
    ok("neg-check-cert", "--cert", cert.toString(), "--csr", csr.toString(),
        "--profile", "rootca");
    assertFails("found no certificate profile", "check-cert", "--cert", cert.toString(),
        "--csr", csr.toString(), "--profile", "no-such-profile");
  }

  @Test
  public void initCaQaFailsWithInvalidConf() throws Exception {
    String conf = Files.readString(qaConf);
    try {
      Files.writeString(qaConf, "{invalid");
      Result r = run(new QaShellMain.RootCommand(), "init-caqa");
      Assert.assertTrue(r.out, r.out.contains("initialization failed"));
      Assert.assertNotEquals("exit code of failed init-caqa", 0, r.exitCode);
    } finally {
      Files.writeString(qaConf, conf);
      ok("init-caqa");
    }
  }

  // ----- checks of the CA configuration -----

  /** The command with all URI options of rootca1 (each list or null). */
  private static String[] withNoUris(String... args) throws Exception {
    CaUris uris = server.getCa(CA).base().caUris();
    List<String> ret = new ArrayList<>(List.of(args));
    addUriOptions(ret, "--ca-cert-uri", uris.cacertUris());
    addUriOptions(ret, "--ocsp-uri", uris.ocspUris());
    addUriOptions(ret, "--crl-uri", uris.crlUris());
    addUriOptions(ret, "--deltacrl-uri", uris.deltaCrlUris());
    return ret.toArray(new String[0]);
  }

  private static void addUriOptions(List<String> args, String option, List<String> uris) {
    if (uris == null || uris.isEmpty()) {
      args.add(option);
      args.add("null");
    } else {
      for (String uri : uris) {
        args.add(option);
        args.add(uri);
      }
    }
  }

  @Test
  public void caCheck() throws Exception {
    ok(withNoUris("ca-check", "--name", CA, "--permission", "all", "--sn-len", "20",
        "--status", "active"));
    assertFails("serial number length", withNoUris("ca-check", "--name", CA, "--sn-len", "10"));
    ok(withNoUris("neg-ca-check", "--name", CA, "--sn-len", "10"));
    assertFails("exception expected", withNoUris("neg-ca-check", "--name", CA,
        "--sn-len", "20"));
    assertFails("Unknown CA no-such-ca", "ca-check", "--name", "no-such-ca");
  }

  @Test
  public void caCheckWithoutUris() throws Exception {
    // without URI options the URIs are not checked
    ok("ca-check", "--name", CA, "--permission", "all");

    // a CA with URIs: only the given URIs are checked
    String name = "qa-uris-" + COUNTER.incrementAndGet();
    CaEntry entry = CaH2TestEnv.newCaEntry(name);
    entry.base().setCaUris(new CaUris(null, List.of("http://ocsp.example.org"),
        List.of("http://crl.example.org"), null));
    server.generateRootCa(entry, "rootca", "CN=" + name + ",O=myorg,C=DE", "1", null, null);

    ok("ca-check", "--name", name, "--ocsp-uri", "http://ocsp.example.org");
    ok("ca-check", "--name", name, "--permission", "all");
  }

  @Test
  public void caCheckCertchain() throws Exception {
    // rootca1 has no certificate chain: an expected chain does not match
    assertFails("certchain", withNoUris("ca-check", "--name", CA,
        "--certchain", caCertFile.toString()));
  }

  @Test
  public void caAliasAndCaProfileCheck() throws Exception {
    String alias = "qa-alias-" + COUNTER.incrementAndGet();
    server.addCaAlias(alias, CA);
    ok("caalias-check", "--ca", CA, "--alias", alias);
    ok("neg-caalias-check", "--ca", CA, "--alias", "no-such-alias");
    server.removeCaAlias(alias);

    ok("caprofile-check", "--ca", CA, "--profile", PROFILE);
    assertFails("CA-Profile unmatch", "caprofile-check", "--ca", CA,
        "--profile", PROFILE + ":some-alias");
    ok("neg-caprofile-check", "--ca", CA, "--profile", "no-such-profile");
  }

  @Test
  public void profileCheck() throws Exception {
    Path conf = file("profile.json");
    Files.writeString(conf, server.getCertprofile(PROFILE).conf());
    ok("profile-check", "--name", PROFILE, "--conf-file", conf.toString());
    ok("profile-check", "--name", PROFILE, "--type", "xijson", "--conf-file", conf.toString());
    Path other = file("other.json");
    Files.writeString(other, server.getCertprofile("rootca").conf());
    assertFails("conf: is", "profile-check", "--name", PROFILE, "--conf-file", other.toString());
  }

  @Test
  public void requestorAndCareqCheck() throws Exception {
    String name = "qa-requestor-" + COUNTER.incrementAndGet();
    X509Cert cert = certOf(newKeystore());
    Path certFile = file("requestor.der");
    Files.write(certFile, cert.getEncoded());
    server.addRequestor(new RequestorEntry(new NameId(null, name), RequestorEntry.TYPE_CERT,
        Base64.encodeToString(cert.getEncoded())));
    ok("requestor-check", "--name", name, "--cert", certFile.toString());
    Path otherCert = file("other.der");
    Files.write(otherCert, certOf(newKeystore()).getEncoded());
    assertFails("differ", "requestor-check", "--name", name, "--cert", otherCert.toString());

    server.addRequestorToCa(new CaHasRequestorEntry(new NameId(null, name),
        new Permissions(Set.of("enroll_cert", "revoke_cert")), List.of(PROFILE)), CA);
    ok("careq-check", "--ca", CA, "--requestor", name, "--permission", "enroll_cert",
        "--permission", "revoke_cert", "--profile", PROFILE);
    assertFails("permissions", "careq-check", "--ca", CA, "--requestor", name,
        "--permission", "enroll_cert");
    ok("neg-careq-check", "--ca", CA, "--requestor", name, "--profile", "rootca");
  }

  @Test
  public void careqCheckProfileOrder() throws Exception {
    // the profiles are a set: the order of the options does not matter
    String name = "qa-requestor-" + COUNTER.incrementAndGet();
    server.addRequestor(new RequestorEntry(new NameId(null, name), RequestorEntry.TYPE_CERT,
        Base64.encodeToString(certOf(newKeystore()).getEncoded())));
    server.addRequestorToCa(new CaHasRequestorEntry(new NameId(null, name),
        new Permissions(Set.of("enroll_cert")), List.of(PROFILE, "rootca")), CA);
    ok("careq-check", "--ca", CA, "--requestor", name, "--profile", PROFILE,
        "--profile", "rootca");
    ok("careq-check", "--ca", CA, "--requestor", name, "--profile", "rootca",
        "--profile", PROFILE);
  }

  @Test
  public void signerCheck() throws Exception {
    String name = "qa-signer-" + COUNTER.incrementAndGet();
    String conf = "password=" + PWD + ",algo=SHA256WITHECDSA,keystore=base64:"
        + Base64.encodeToString(Files.readAllBytes(newKeystore()));
    server.addSigner(new SignerEntry(name, "pkcs12", conf, null));
    ok("signer-check", "--name", name, "--conf", conf);
    assertFails("conf: is", "signer-check", "--name", name, "--conf", "password=other");
    ok("neg-signer-check", "--name", "no-such-signer");
  }

  @Test
  public void publisherAndCapubCheck() throws Exception {
    String name = "qa-publisher-" + COUNTER.incrementAndGet();
    String conf = "datasource=ocsp,publish.goodcerts=true";
    server.addPublisher(new PublisherEntry(new NameId(null, name), "ocsp", conf));
    ok("publisher-check", "--name", name, "--type", "ocsp", "--conf", conf);
    assertFails("type: is", "publisher-check", "--name", name, "--type", "other",
        "--conf", conf);

    server.addPublisherToCa(name, CA);
    ok("capub-check", "--ca", CA, "--publisher", name);
    ok("neg-capub-check", "--ca", CA, "--publisher", "no-such-publisher");
    server.removePublisherFromCa(name, CA);
  }

  @Test
  public void publisherCheckPartial() throws Exception {
    // only the given values are checked
    String name = "qa-publisher-" + COUNTER.incrementAndGet();
    server.addPublisher(new PublisherEntry(new NameId(null, name), "ocsp",
        "datasource=ocsp,publish.goodcerts=true"));
    ok("publisher-check", "--name", name, "--type", "ocsp");
  }

  // ----- negative wrappers of the management commands -----

  @Test
  public void negMgmtCommands() throws Exception {
    // the wrapped command fails: success
    ok("neg-enroll-cert", "--ca", CA, "--profile", "no-such-profile",
        "--subject", "CN=neg.example.org", "--key-password", PWD,
        "--out", file("neg.der").toString());
    ok("neg-profile-rm", "no-such-profile", "-f");
    ok("neg-caalias-rm", "no-such-alias", "-f");
    ok("neg-requestor-rm", "no-such-requestor", "-f");

    // the wrapped command succeeds: failure
    String alias = "neg-alias-" + COUNTER.incrementAndGet();
    assertFails("exception expected", "neg-caalias-add", "--ca", CA, "--alias", alias);
    Assert.assertEquals(CA, server.getCaNameForAlias(alias));
    server.removeCaAlias(alias);
  }

  // ----- keypool and speed tests -----

  @Test
  public void fillKeypool() throws Exception {
    Path dbConf = env.extraDbConf("keypool");
    ok("fill-keypool", "--db-conf", dbConf.toString(), "--num", "2", "--keyspec", "P256",
        "--password", PWD);
    Assert.assertTrue(count(dbConf, "KEYPOOL") >= 2);
    assertFails("invalid num", "fill-keypool", "--db-conf", dbConf.toString(), "--num", "0",
        "--password", PWD);
  }

  @Test
  public void speedP12() throws Exception {
    ok("speed-keypair-p12", "--keyspec", "P256", "--duration", "1s", "--thread", "1");
    ok("speed-sign-p12", "--keyspec", "P256", "--sig-algo", "SHA256withECDSA",
        "--duration", "1s", "--thread", "1");
  }

  // ----- helpers -----

  private static long count(Path dbConf, String table) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(dbConf)) {
      props.load(in);
    }
    try (DataSourceWrapper ds = new DataSourceFactory().createDataSource("count", props);
         Connection conn = ds.getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + table)) {
      rs.next();
      return rs.getLong(1);
    }
  }

  private static String jsonList(List<String> list) {
    StringBuilder sb = new StringBuilder("[");
    if (list != null) {
      for (String s : list) {
        sb.append(sb.length() == 1 ? "" : ", ").append('"').append(s).append('"');
      }
    }
    return sb.append(']').toString();
  }

  private static String path(Path path) {
    return path.toAbsolutePath().toString().replace("\\", "/");
  }

  private static Path newKeystore() throws Exception {
    Path p12 = file("key.p12");
    Files.write(p12, KeyUtil.generateX509KeyPair3(KeySpec.P256,
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

  /** Runs the command, asserts success and returns the output. */
  private static String ok(String... args) {
    Result r = run(new QaShellMain.RootCommand(), args);
    Assert.assertEquals(String.join(" ", args) + "\nout: " + r.out + "\nerr: " + r.err,
        0, r.exitCode);
    return r.out;
  }

  /** Runs the command and asserts that it fails with the given text in the error output. */
  private static void assertFails(String expectedText, String... args) {
    Result r = run(new QaShellMain.RootCommand(), args);
    Assert.assertNotEquals(String.join(" ", args) + "\nout: " + r.out, 0, r.exitCode);
    if (expectedText != null) {
      Assert.assertTrue("expected '" + expectedText + "' in\n" + r.err,
          r.err.contains(expectedText));
    }
  }

  private static Result run(Object rootCommand, String... args) {
    InputStream oldIn = System.in;
    PrintStream oldOut = System.out;
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    ByteArrayOutputStream sysOut = new ByteArrayOutputStream();
    try {
      System.setIn(new ByteArrayInputStream(new byte[0]));
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
