// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.BasicOCSPResponse;
import org.xipki.asn1.ocsp.CertID;
import org.xipki.asn1.ocsp.OCSPRequest;
import org.xipki.asn1.ocsp.OCSPResponse;
import org.xipki.asn1.ocsp.OCSPResponseStatus;
import org.xipki.asn1.ocsp.OcspCertStatus;
import org.xipki.asn1.ocsp.Request;
import org.xipki.asn1.ocsp.SingleResponse;
import org.xipki.asn1.ocsp.TBSRequest;
import org.xipki.asn1.x509.CRLReason;
import org.xipki.codec.Base64;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.util.ConfPairs;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.ScriptRunner;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.Securities;
import org.xipki.pkix.cert.CertRevocationInfo;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.audit.Audits;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.password.Passwords;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Integration test of {@link OcspServer} with the store type {@code xipki-ca-db} on an
 * in-memory H2 CA database, initialized with the SQL script of the distribution. The CAs and
 * certificate entries are inserted directly into the database.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspServerH2Test {

  private static final String SQL_SCRIPT =
      "../assemblies/xipki-setup/src/assembly/unfiltered/" +
          "xipki-mgmt-cli/xipki/sql/h2/ca-init.h2.sql";

  private static final String PASSWORD = "CHANGEIT";

  private static final BigInteger SN_GOOD = BigInteger.valueOf(0x1001);

  private static final BigInteger SN_REVOKED = BigInteger.valueOf(0x1002);

  private static final BigInteger SN_ON_HOLD = BigInteger.valueOf(0x1003);

  private static final BigInteger SN_EXPIRED = BigInteger.valueOf(0x1004);

  private static final BigInteger SN_UNKNOWN = BigInteger.valueOf(0x1999);

  private static final BigInteger SN_OF_REVOKED_CA = BigInteger.valueOf(0x2001);

  /** Revocation time of {@link #SN_REVOKED}, in seconds. */
  private static final Instant REVOCATION_TIME =
      Instant.now().minus(2, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);

  private static Path workDir;

  private static DataSourceWrapper datasource;

  private static Securities securities;

  private static OcspServer server;

  /** Mode RFC 6960. */
  private static Responder responder;

  /** Mode RFC 2560, otherwise as {@link #responder}. */
  private static Responder rfc2560Responder;

  /** CA 1, also the OCSP signer. */
  private static X509Cert ca1Cert;

  /** CA 2, revoked. */
  private static X509Cert ca2Cert;

  @BeforeClass
  public static void init() throws Exception {
    workDir = Files.createTempDirectory("xipki-ocsp-h2-test");
    Passwords.init(workDir.toString());
    Audits.init("noop", new ConfPairs(), workDir.toString());

    Path dbConf = writeDbConf("ca_" + UUID.randomUUID().toString().replace("-", ""));
    datasource = createDatasource(dbConf);
    ScriptRunner.runScript(datasource, Paths.get(SQL_SCRIPT).toString(),
        workDir.resolve("ca-init.log"), workDir.resolve("ca-init.error.log"));

    byte[] ca1Keystore = newKeystore();
    ca1Cert = certOf(ca1Keystore);
    ca2Cert = certOf(newKeystore());

    Instant now = Instant.now();
    Instant notBefore = now.minus(30, ChronoUnit.DAYS);
    Instant notAfter = now.plus(30, ChronoUnit.DAYS);
    try (Connection conn = datasource.getConnection()) {
      exec(conn, "INSERT INTO PROFILE (ID,NAME) VALUES (1,'profile1')");
      exec(conn, "INSERT INTO REQUESTOR (ID,NAME) VALUES (1,'requestor1')");
      addCa(conn, 1, "ca1", ca1Cert, null);
      addCa(conn, 2, "ca2", ca2Cert, new CertRevocationInfo(CrlReason.CA_COMPROMISE,
          now.minus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS), null));

      addCert(conn, 1, 1, SN_GOOD, notBefore, notAfter, null);
      addCert(conn, 2, 1, SN_REVOKED, notBefore, notAfter,
          new CertRevocationInfo(CrlReason.KEY_COMPROMISE, REVOCATION_TIME, null));
      addCert(conn, 3, 1, SN_ON_HOLD, notBefore, notAfter,
          new CertRevocationInfo(CrlReason.CERTIFICATE_HOLD, REVOCATION_TIME, null));
      addCert(conn, 4, 1, SN_EXPIRED, notBefore, now.minus(1, ChronoUnit.DAYS), null);
      addCert(conn, 5, 2, SN_OF_REVOKED_CA, notBefore, notAfter, null);
    }

    securities = new Securities();
    securities.init(null, workDir.toString());

    server = new OcspServer(workDir.toString());
    server.setSecurityFactory(securities.securityFactory());
    server.setConfFile(writeResponderConf(dbConf, ca1Keystore).toString());
    server.init(true);
    responder = server.getResponder("responder1");
    Assert.assertNotNull("responder1", responder);
    rfc2560Responder = server.getResponder("responder2");
    Assert.assertNotNull("responder2", rfc2560Responder);
  }

  @AfterClass
  public static void shutdown() {
    if (server != null) {
      server.close();
    }
    if (datasource != null) {
      datasource.close();
    }
    if (securities != null) {
      securities.close();
    }
  }

  @Test
  public void goodCertificate() throws Exception {
    SingleResponse resp = singleResponse(ca1Cert, SN_GOOD);
    Assert.assertEquals(OcspCertStatus.GOOD, resp.getCertStatus());
    Assert.assertEquals(SN_GOOD, resp.getCertID().serialNumber());
    Assert.assertNotNull("nextUpdate", resp.nextUpdate());
  }

  @Test
  public void revokedCertificate() throws Exception {
    OcspCertStatus status = singleResponse(ca1Cert, SN_REVOKED).getCertStatus();
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(REVOCATION_TIME, status.getRevoked().getRevocationTime().getTime());
    Assert.assertEquals(CRLReason.keyCompromise, status.getRevoked().getRevocationReason());
  }

  @Test
  public void certificateOnHold() throws Exception {
    OcspCertStatus status = singleResponse(ca1Cert, SN_ON_HOLD).getCertStatus();
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.certificateHold, status.getRevoked().getRevocationReason());
  }

  @Test
  public void unknownSerialNumber() throws Exception {
    assertNonIssued(singleResponse(responder, ca1Cert, SN_UNKNOWN).getCertStatus());
    Assert.assertEquals(OcspCertStatus.UNKNOWN,
        singleResponse(rfc2560Responder, ca1Cert, SN_UNKNOWN).getCertStatus());
  }

  @Test
  public void expiredCertificateIsIgnored() throws Exception {
    // ignoreExpiredCert = true: an expired certificate is treated as not issued
    assertNonIssued(singleResponse(responder, ca1Cert, SN_EXPIRED).getCertStatus());
    Assert.assertEquals(OcspCertStatus.UNKNOWN,
        singleResponse(rfc2560Responder, ca1Cert, SN_EXPIRED).getCertStatus());
  }

  @Test
  public void revocationOfCaIsInherited() throws Exception {
    // inheritCaRevocation = true: a certificate of a revoked CA is revoked
    OcspCertStatus status = singleResponse(ca2Cert, SN_OF_REVOKED_CA).getCertStatus();
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.cACompromise, status.getRevoked().getRevocationReason());
  }

  @Test
  public void severalCertificatesInOneRequest() throws Exception {
    BasicOCSPResponse basic = basicResponse(
        request(certId(ca1Cert, SN_GOOD), certId(ca1Cert, SN_REVOKED)));
    List<SingleResponse> responses = toList(basic.getResponses());
    Assert.assertEquals(2, responses.size());
    Assert.assertEquals(OcspCertStatus.GOOD, responses.get(0).getCertStatus());
    Assert.assertNotNull(responses.get(1).getCertStatus().getRevoked());
  }

  @Test
  public void responseIsSignedByTheResponder() throws Exception {
    BasicOCSPResponse basic = basicResponse(request(certId(ca1Cert, SN_GOOD)));
    Assert.assertTrue("response signature", basic.isSignatureValid(
        securities.securityFactory().getContentVerifierFactory(CertVariant.ofX509(ca1Cert))));
  }

  @Test
  public void unknownIssuerIsRejected() throws Exception {
    // unknownIssuerBehaviour = malformedRequest
    X509Cert otherIssuer = certOf(newKeystore());
    OCSPResponse resp = answer(request(certId(otherIssuer, SN_GOOD)));
    Assert.assertEquals(OCSPResponseStatus.MALFORMED_REQUEST, resp.getResponseStatus());
  }

  @Test
  public void malformedRequestIsRejected() throws Exception {
    OCSPResponse resp = answer(new byte[] {0x30, 0x03, 0x30, 0x01, 0x30});
    Assert.assertEquals(OCSPResponseStatus.MALFORMED_REQUEST, resp.getResponseStatus());
  }

  @Test
  public void healthCheck() {
    Assert.assertTrue(server.healthCheck(responder));
  }

  // ----- helpers -----

  /**
   * RFC 6960, Section 2.2: a non-issued certificate is answered as revoked, with the reason
   * certificateHold and the revocation time 1970-01-01T00:00:00Z.
   */
  private static void assertNonIssued(OcspCertStatus status) {
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.certificateHold, status.getRevoked().getRevocationReason());
    Assert.assertEquals(Instant.EPOCH, status.getRevoked().getRevocationTime().getTime());
  }

  private static SingleResponse singleResponse(X509Cert issuer, BigInteger serial)
      throws Exception {
    return singleResponse(responder, issuer, serial);
  }

  private static SingleResponse singleResponse(Responder responder, X509Cert issuer,
                                               BigInteger serial) throws Exception {
    BasicOCSPResponse basic = basicResponse(responder, request(certId(issuer, serial)));
    List<SingleResponse> responses = toList(basic.getResponses());
    Assert.assertEquals(1, responses.size());
    return responses.get(0);
  }

  private static List<SingleResponse> toList(SingleResponse.Seq0 seq) {
    List<SingleResponse> list = new ArrayList<>();
    for (Object entry : seq) {
      list.add((SingleResponse) entry);
    }
    return list;
  }

  private static BasicOCSPResponse basicResponse(byte[] request) throws Exception {
    return basicResponse(responder, request);
  }

  private static BasicOCSPResponse basicResponse(Responder responder, byte[] request)
      throws Exception {
    OCSPResponse resp = OCSPResponse.fromEncoded(
        server.answer(responder, request, false).response());
    Assert.assertEquals(OCSPResponseStatus.SUCCESSFUL, resp.getResponseStatus());
    return resp.getBasicOCSPResponse();
  }

  private static OCSPResponse answer(byte[] request) throws Exception {
    return OCSPResponse.fromEncoded(server.answer(responder, request, false).response());
  }

  private static byte[] request(CertID... certIds) throws Exception {
    List<Request> requests = new ArrayList<>(certIds.length);
    for (CertID certId : certIds) {
      requests.add(new Request(certId, null));
    }
    TBSRequest tbs = new TBSRequest(null, new Request.Seq0(requests), null);
    return new OCSPRequest(tbs, null).getEncoded();
  }

  private static CertID certId(X509Cert issuer, BigInteger serial) throws Exception {
    HashAlgo hashAlgo = HashAlgo.SHA1;
    Asn1OctetString nameHash = new Asn1OctetString(hashAlgo.hash(issuer.subject().getEncoded()));
    Asn1OctetString keyHash = new Asn1OctetString(hashAlgo.hash(
        issuer.getCert().getTBSCertificate().getSubjectPublicKeyInfo().subjectPublicKey()));
    return new CertID(hashAlgo.algorithmIdentifier(), nameHash, keyHash,
        new Asn1Integer(serial));
  }

  private static byte[] newKeystore() throws Exception {
    KeystoreGenerationParameters params =
        new KeystoreGenerationParameters(PASSWORD.toCharArray());
    return KeyUtil.generateX509KeyPair3(KeySpec.P256, params).keystore();
  }

  private static X509Cert certOf(byte[] keystore) throws Exception {
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, PASSWORD.toCharArray(), null,
          PASSWORD.toCharArray(), (X509Cert) null).certChain()[0];
    }
  }

  private static void addCa(Connection conn, int id, String name, X509Cert cert,
                            CertRevocationInfo revInfo) throws Exception {
    try (PreparedStatement ps = conn.prepareStatement(
        "INSERT INTO CA (ID,NAME,SUBJECT,REV_INFO,CERT) VALUES (?,?,?,?,?)")) {
      ps.setInt(1, id);
      ps.setString(2, name);
      ps.setString(3, cert.subjectText());
      ps.setString(4, revInfo == null ? null : revInfo.encode());
      ps.setString(5, Base64.encodeToString(cert.getEncoded()));
      ps.executeUpdate();
    }
  }

  private static void addCert(Connection conn, long id, int caId, BigInteger serial,
                              Instant notBefore, Instant notAfter, CertRevocationInfo revInfo)
      throws Exception {
    // the certificate itself is not evaluated by the store: use a placeholder
    byte[] placeholder = serial.toByteArray();
    try (PreparedStatement ps = conn.prepareStatement("INSERT INTO CERT "
        + "(ID,CA_ID,SN,PID,RID,FP_S,LUPDATE,NBEFORE,NAFTER,REV,RR,RT,EE,SUBJECT,CRL_SCOPE,"
        + "SHA1,CERT) VALUES (?,?,?,1,1,?,?,?,?,?,?,?,1,?,0,?,?)")) {
      int idx = 1;
      ps.setLong(idx++, id);
      ps.setInt(idx++, caId);
      ps.setString(idx++, serial.toString(16));
      ps.setLong(idx++, id); // FP_S
      ps.setLong(idx++, Instant.now().getEpochSecond());
      ps.setLong(idx++, notBefore.getEpochSecond());
      ps.setLong(idx++, notAfter.getEpochSecond());
      ps.setInt(idx++, revInfo == null ? 0 : 1);
      if (revInfo == null) {
        ps.setNull(idx++, java.sql.Types.SMALLINT);
        ps.setNull(idx++, java.sql.Types.BIGINT);
      } else {
        ps.setInt(idx++, revInfo.reason().code());
        ps.setLong(idx++, revInfo.revocationTime().getEpochSecond());
      }
      ps.setString(idx++, "CN=ee-" + serial.toString(16));
      ps.setString(idx++, Base64.encodeToString(HashAlgo.SHA1.hash(placeholder)));
      ps.setString(idx, Base64.encodeToString(placeholder));
      ps.executeUpdate();
    }
  }

  private static void exec(Connection conn, String sql) throws Exception {
    try (PreparedStatement ps = conn.prepareStatement(sql)) {
      ps.executeUpdate();
    }
  }

  private static Path writeDbConf(String dbName) throws IOException {
    String conf = "dataSourceClassName = org.h2.jdbcx.JdbcDataSource\n"
        + "dataSource.url = jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1\n"
        + "dataSource.user = sa\n"
        + "dataSource.password = \n"
        + "autoCommit = true\n"
        + "maximumPoolSize = 5\n"
        + "minimumIdle = 1\n";
    Path file = workDir.resolve("ca-db.properties");
    Files.writeString(file, conf);
    return file;
  }

  private static DataSourceWrapper createDatasource(Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return new DataSourceFactory().createDataSource("ocsp-test", props);
  }

  private static Path writeResponderConf(Path dbConf, byte[] signerKeystore) throws IOException {
    String dbConfPath = dbConf.toAbsolutePath().toString().replace("\\", "/");
    String conf = "{\n"
        + "  \"master\": true,\n"
        + "  \"unknownIssuerBehaviour\": \"malformedRequest\",\n"
        + "  \"datasources\": [{\"name\": \"datasource1\","
        + " \"conf\": {\"file\": \"" + dbConfPath + "\"}}],\n"
        + "  \"requestOptions\": [{\n"
        + "    \"name\": \"request1\",\n"
        + "    \"hashAlgorithms\": [\"SHA1\", \"SHA256\"],\n"
        + "    \"maxRequestListCount\": 10,\n"
        + "    \"maxRequestSize\": 4096,\n"
        + "    \"nonce\": {\"maxLen\": 32, \"minLen\": 4, \"occurrence\": \"optional\"},\n"
        + "    \"signatureRequired\": false,\n"
        + "    \"supportsHttpGet\": true,\n"
        + "    \"validateSignature\": false,\n"
        + "    \"versions\": [\"v1\"]\n"
        + "  }],\n"
        + "  \"responders\": [{\n"
        + "    \"name\": \"responder1\",\n"
        + "    \"inheritCaRevocation\": true,\n"
        + "    \"mode\": \"RFC6960\",\n"
        + "    \"request\": \"request1\",\n"
        + "    \"response\": \"response1\",\n"
        + "    \"servletPaths\": [\"/\"],\n"
        + "    \"signer\": \"signer1\",\n"
        + "    \"stores\": [\"store1\"]\n"
        + "  }, {\n"
        + "    \"name\": \"responder2\",\n"
        + "    \"inheritCaRevocation\": true,\n"
        + "    \"mode\": \"RFC2560\",\n"
        + "    \"request\": \"request1\",\n"
        + "    \"response\": \"response1\",\n"
        + "    \"servletPaths\": [\"/rfc2560\"],\n"
        + "    \"signer\": \"signer1\",\n"
        + "    \"stores\": [\"store1\"]\n"
        + "  }],\n"
        + "  \"responseOptions\": [{\n"
        + "    \"name\": \"response1\",\n"
        + "    \"embedCertsMode\": \"CERT\",\n"
        + "    \"includeCerthash\": false,\n"
        + "    \"includeInvalidityDate\": false,\n"
        + "    \"includeRevReason\": true,\n"
        + "    \"responderIdByName\": true\n"
        + "  }],\n"
        + "  \"signers\": [{\n"
        + "    \"name\": \"signer1\",\n"
        + "    \"type\": \"pkcs12\",\n"
        + "    \"key\": \"password=" + PASSWORD + ",keystore=base64:"
        + Base64.encodeToString(signerKeystore) + "\"\n"
        + "  }],\n"
        + "  \"stores\": [{\n"
        + "    \"name\": \"store1\",\n"
        + "    \"ignoreExpiredCert\": true,\n"
        + "    \"ignoreNotYetValidCert\": true,\n"
        + "    \"includeArchiveCutoff\": false,\n"
        + "    \"includeCrlId\": false,\n"
        + "    \"retentionInterval\": -1,\n"
        + "    \"minNextUpdatePeriod\": \"1d\",\n"
        + "    \"unknownCertBehaviour\": \"unknown\",\n"
        + "    \"updateInterval\": \"10m\",\n"
        + "    \"source\": {\"datasource\": \"datasource1\", \"type\": \"xipki-ca-db\","
        + " \"conf\": {}}\n"
        + "  }]\n"
        + "}\n";
    Path file = workDir.resolve("ocsp-responder.json");
    Files.writeString(file, conf);
    return file;
  }

}
