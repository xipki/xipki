// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.cert.CtLog;
import org.xipki.asn1.cert.CtLog.AddPreChainRequest;
import org.xipki.asn1.cert.CtLog.AddPreChainResponse;
import org.xipki.asn1.cert.CtLog.DigitallySigned;
import org.xipki.asn1.cert.CtLog.SignedCertificateTimestamp;
import org.xipki.asn1.cert.CtLog.SignedCertificateTimestampList;
import org.xipki.asn1.x509.Certificate;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.json.JsonBuilder;
import org.xipki.codec.json.JsonParser;
import org.xipki.codec.x509.id.ExtensionOIDs;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.misc.NameId;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Certificate Transparency (RFC 6962): the CA submits the precertificate to the CT logs
 * ({@code CtLogClient}), verifies the SCTs with the public keys of the key directory
 * ({@code CtLogPublicKeyFinder}) and embeds them in the certificate. The CT logs are emulated
 * by an HTTP server in this test.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogH2Test {

  private static final String PROFILE_CT = "tls-ct";

  private static TestCtLog ctlog;

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  @BeforeClass
  public static void init() throws Exception {
    Path keyDir = Files.createTempDirectory("xipki-ctlog-keys");
    ctlog = new TestCtLog();
    // the keys of log1 and log2 are known to the CA, that of "unknown" not
    List<Path> keys = List.of(ctlog.writePublicKey("log1", keyDir),
        ctlog.writePublicKey("log2", keyDir), ctlog.writePublicKey("tampered", keyDir));
    env = new CaH2TestEnv(keys);
    caManager = env.caManager();

    // the TLS profile with the SCT extension
    String tls;
    try (InputStream in = CtLogH2Test.class.getResourceAsStream(
        "/certprofile/certprofile-" + CaH2TestEnv.PROFILE_TLS + ".json")) {
      tls = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    String ct = tls.replaceFirst("\"extensions\": \\[",
        "\"extensions\": [\n    {\"type\": \"SignedCertificateTimestampList\", \"required\": true},");
    Assert.assertNotEquals("SCT extension added", tls, ct);
    caManager.addCertprofile(new CertprofileEntry(new NameId(null, PROFILE_CT), "xijson", ct));
    caManager.addCertprofileToCa(PROFILE_CT, CaH2TestEnv.CA_NAME);
  }

  @AfterClass
  public static void shutdown() {
    if (ctlog != null) {
      ctlog.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void sctsOfAllLogsAreVerifiedAndEmbedded() throws Exception {
    String ca = newCa("ct-ok", ctlog.url("log1") + ";" + ctlog.url("log2"));
    X509Cert caCert = caManager.getCaCerts(ca).get(0).x509Cert();
    int requestsBefore = ctlog.requests();

    X509Cert cert = issue(ca, PROFILE_CT, "ct-ok.example.org");
    Assert.assertEquals("one request per log", requestsBefore + 2, ctlog.requests());

    // the submitted chain: precertificate (with poison extension), issuer
    List<byte[]> chain = ctlog.lastChain();
    Certificate precert = Certificate.fromEncoded(chain.get(0));
    Assert.assertNotNull("poison extension in the precertificate", precert.getTBSCertificate()
        .getExtensions().getExtension(ExtensionOIDs.id_precertificate));
    Assert.assertArrayEquals(caCert.getEncoded(), chain.get(1));

    // the certificate: no poison extension, the SCTs of both logs
    Assert.assertNull(extension(cert, ExtensionOIDs.id_precertificate));
    List<SignedCertificateTimestamp> scts = scts(cert);
    Assert.assertEquals(2, scts.size());
    Assert.assertArrayEquals(ctlog.logId("log1"), scts.get(0).logId());
    Assert.assertArrayEquals(ctlog.logId("log2"), scts.get(1).logId());

    // as a relying party: each SCT is valid for the issued certificate
    for (SignedCertificateTimestamp sct : scts) {
      String log = Arrays.equals(sct.logId(), ctlog.logId("log1")) ? "log1" : "log2";
      Assert.assertTrue("SCT of " + log + " valid for the certificate",
          verify(sct, cert, caCert, ctlog.publicKey(log)));
    }
  }

  @Test
  public void profileWithoutSctExtensionDoesNotUseTheLogs() throws Exception {
    String ca = newCa("ct-noext", ctlog.url("log1"));
    int requestsBefore = ctlog.requests();
    X509Cert cert = issue(ca, CaH2TestEnv.PROFILE_TLS, "ct-noext.example.org");
    Assert.assertEquals(requestsBefore, ctlog.requests());
    Assert.assertNull(extension(cert, ExtensionOIDs.id_SignedCertificateTimestampList));
  }

  @Test
  public void sctRequiredButCtLogOfCaDisabled() throws Exception {
    // the CA of the environment has no CT log control
    assertNotIssued(CaH2TestEnv.CA_NAME, "ct-disabled.example.org");
  }

  @Test
  public void invalidSctSignatureIsRejected() throws Exception {
    String ca = newCa("ct-tampered", ctlog.url("log1") + ";" + ctlog.url("tampered"));
    assertNotIssued(ca, "ct-tampered.example.org");
  }

  @Test
  public void errorOfTheLogIsRejected() throws Exception {
    assertNotIssued(newCa("ct-error", ctlog.url("error")), "ct-error.example.org");
  }

  @Test
  public void unreachableLogIsRejected() throws Exception {
    int port;
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      port = socket.getLocalPort();
    }
    assertNotIssued(newCa("ct-down", "http://127.0.0.1:" + port + "/ctlog/down/"),
        "ct-down.example.org");
  }

  /** The key of the log is not in the key directory: the SCT cannot be verified. */
  @Test
  public void sctOfUnknownLogIsRejected() throws Exception {
    assertNotIssued(newCa("ct-unknown", ctlog.url("log1") + ";" + ctlog.url("unknown")),
        "ct-unknown.example.org");
  }

  /** CT enabled, but no public keys of CT logs configured: the CA is not started. */
  @Test
  public void caWithoutCtLogKeysIsNotStarted() throws Exception {
    try (CaH2TestEnv noKeysEnv = new CaH2TestEnv()) {
      CaManagerImpl manager = noKeysEnv.caManager();
      CaEntry entry = CaH2TestEnv.newCaEntry("ct-nokeys");
      entry.base().setCtlogControl(new CtlogControl("enabled=true,servers=" + ctlog.url("log1")));
      try {
        manager.generateRootCa(entry, "rootca", "CN=ct-nokeys,O=myorg,C=DE", "1", null, null);
      } catch (CaMgmtException ex) {
        // also acceptable: generation rejected
      }
      Assert.assertFalse("CA started", manager.getSuccessfulCaNames().contains("ct-nokeys"));
    }
  }

  // ---------------------------------------------------------------- helpers

  /** A new root CA with the given CT log servers (';'-separated) and both TLS profiles. */
  private static String newCa(String name, String servers) throws Exception {
    CaEntry entry = CaH2TestEnv.newCaEntry(name);
    entry.base().setCtlogControl(new CtlogControl("enabled=true,servers=" + servers));
    caManager.generateRootCa(entry, "rootca", "CN=" + name + ",O=myorg,C=DE", "1", null, null);
    caManager.addCertprofileToCa(CaH2TestEnv.PROFILE_TLS, name);
    caManager.addCertprofileToCa(PROFILE_CT, name);
    return name;
  }

  private static X509Cert issue(String ca, String profile, String commonName) throws Exception {
    return X509Util.parseCert(caManager.generateKeyCert(ca, profile,
        "CN=" + commonName + ",O=myorg,C=DE", null, null).cert());
  }

  /** Issuance with the SCT profile fails, and no certificate is stored. */
  private static void assertNotIssued(String ca, String commonName) throws Exception {
    int before = certCount(ca);
    Assert.assertThrows(CaMgmtException.class, () -> issue(ca, PROFILE_CT, commonName));
    Assert.assertEquals("no certificate stored", before, certCount(ca));
  }

  private static int certCount(String ca) throws Exception {
    int caId = caManager.idNameMap().getCa(ca).id();
    try (Connection conn = env.caDatasource().getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM CERT WHERE CA_ID=" + caId)) {
      rs.next();
      return rs.getInt(1);
    }
  }

  /**
   * The SCTs of the certificate. RFC 6962 3.3: the extnValue contains the DER encoding of
   * SignedCertificateTimestampList ::= OCTET STRING, which contains the TLS-encoded list.
   */
  private static List<SignedCertificateTimestamp> scts(X509Cert cert) throws Exception {
    byte[] extnValue = extension(cert, ExtensionOIDs.id_SignedCertificateTimestampList)
        .extnValue();
    byte[] tlsEncoded = Asn1OctetString.fromEncoded(extnValue).getOctets();
    CtLog.SerializedSCT list = SignedCertificateTimestampList.getInstance(tlsEncoded).sctList();
    List<SignedCertificateTimestamp> ret = new ArrayList<>(list.size());
    for (int i = 0; i < list.size(); i++) {
      ret.add(list.get(i));
    }
    return ret;
  }

  private static org.xipki.asn1.x509.Extension extension(X509Cert cert,
      org.xipki.codec.asn1.Asn1Oid type) {
    return cert.getCert().getTBSCertificate().getExtensions().getExtension(type);
  }

  /** Verifies the SCT for the issued certificate as specified in RFC 6962, section 3.2. */
  private static boolean verify(SignedCertificateTimestamp sct, X509Cert cert, X509Cert caCert,
                                PublicKey logKey) throws Exception {
    byte[] issuerKeyHash = HashAlgo.SHA256.hash(caCert.subjectPublicKeyInfo().getEncoded());
    byte[] tbs = CtLog.getPreCertTbsCert(cert.getCert().getTBSCertificate());
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initVerify(logKey);
    CtLog.update(sig, (byte) sct.version(), sct.timestamp(), sct.extensions(), issuerKeyHash, tbs);
    return sig.verify(sct.digitallySigned().signature());
  }

  /**
   * Emulation of CT logs (RFC 6962 add-pre-chain) under {@code /ctlog/<name>/}: each log has
   * its own P-256 key. The log {@code tampered} changes the timestamp after signing, the log
   * {@code error} answers with HTTP 500.
   */
  private static final class TestCtLog implements AutoCloseable {

    private final HttpServer server;

    private final Map<String, KeyPair> keys = new HashMap<>();

    private int requests;

    private List<byte[]> lastChain;

    TestCtLog() throws Exception {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      for (String name : List.of("log1", "log2", "tampered", "unknown", "error")) {
        keys.put(name, kpg.generateKeyPair());
      }
      server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
      server.createContext("/ctlog", this::serve);
      server.start();
    }

    String url(String name) {
      return "http://127.0.0.1:" + server.getAddress().getPort() + "/ctlog/" + name + "/";
    }

    PublicKey publicKey(String name) {
      return keys.get(name).getPublic();
    }

    byte[] logId(String name) {
      return HashAlgo.SHA256.hash(publicKey(name).getEncoded());
    }

    Path writePublicKey(String name, Path dir) throws IOException {
      Path file = dir.resolve(name + ".der");
      Files.write(file, publicKey(name).getEncoded());
      return file;
    }

    synchronized int requests() {
      return requests;
    }

    synchronized List<byte[]> lastChain() {
      return lastChain;
    }

    @Override
    public void close() {
      server.stop(0);
    }

    private void serve(HttpExchange exchange) throws IOException {
      try {
        // /ctlog/<name>/ct/v1/add-pre-chain/
        String[] tokens = exchange.getRequestURI().getPath().split("/");
        String name = tokens[2];
        Assert.assertEquals("ct/v1/add-pre-chain",
            String.join("/", tokens[3], tokens[4], tokens[5]));
        Assert.assertEquals("POST", exchange.getRequestMethod());

        byte[] body = exchange.getRequestBody().readAllBytes();
        AddPreChainRequest req = AddPreChainRequest.parse(
            JsonParser.parseMap(new String(body, StandardCharsets.UTF_8), false));
        synchronized (this) {
          requests++;
          lastChain = req.chain();
        }

        if ("error".equals(name)) {
          exchange.sendResponseHeaders(500, -1);
          return;
        }

        Certificate precert = Certificate.fromEncoded(req.chain().get(0));
        Certificate issuer = Certificate.fromEncoded(req.chain().get(1));
        byte[] issuerKeyHash = HashAlgo.SHA256.hash(
            issuer.getSubjectPublicKeyInfo().getEncoded());
        byte[] tbs = CtLog.getPreCertTbsCert(precert.getTBSCertificate());

        long timestamp = System.currentTimeMillis();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(keys.get(name).getPrivate());
        CtLog.update(sig, (byte) 0, timestamp, null, issuerKeyHash, tbs);
        DigitallySigned ds = new DigitallySigned(new CtLog.SignatureAndHashAlgorithm(
            CtLog.HashAlgorithm.sha256, CtLog.SignatureAlgorithm.ecdsa), sig.sign());

        if ("tampered".equals(name)) {
          timestamp++;
        }

        byte[] resp = JsonBuilder.toJson(new AddPreChainResponse((byte) 0, logId(name),
            timestamp, null, ds.getEncoded()).toJson()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, resp.length);
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(resp);
        }
      } catch (Exception ex) {
        exchange.sendResponseHeaders(500, -1);
      } finally {
        exchange.close();
      }
    }

  }

}
