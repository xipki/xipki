// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.OCSPResponse;
import org.xipki.asn1.ocsp.OCSPResponseStatus;
import org.xipki.asn1.ocsp.OcspCertStatus;
import org.xipki.asn1.x509.CRLReason;
import org.xipki.codec.Base64;
import org.xipki.codec.Hex;
import org.xipki.codec.util.ConfPairs;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.Securities;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.audit.Audits;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.password.Passwords;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * The OCSP server with the store type {@code ejbca-db} on an in-memory H2 database with the
 * EJBCA tables {@code CAData} and {@code CertificateData}, created by the unchanged schema script
 * of EJBCA CE (H2 in the mode PostgreSQL) and filled as EJBCA does: the CA data as XML of
 * {@code java.beans.XMLEncoder}, the fingerprints in lower-case hex, the serial numbers in
 * decimal and the times in milliseconds.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspEjbcaStoreH2Test {

  /** The tables of EJBCA CE, unchanged from its PostgreSQL schema script. */
  private static final String SCHEMA = "/ejbca/ejbca-tables.sql";

  private static final String PASSWORD = "CHANGEIT";

  /** EJBCA: CertificateConstants.CERT_ACTIVE. */
  private static final int CERT_ACTIVE = 20;

  /** EJBCA: CertificateConstants.CERT_REVOKED. */
  private static final int CERT_REVOKED = 40;

  /** EJBCA: CertificateConstants.CERTTYPE_ENDENTITY. */
  private static final int CERTTYPE_ENDENTITY = 1;

  /** EJBCA: RevokedCertInfo.NOT_REVOKED. */
  private static final int NOT_REVOKED = -1;

  private static final BigInteger SN_GOOD = new BigInteger("1234567890123456789012345");

  private static final BigInteger SN_REVOKED = BigInteger.valueOf(0x1002);

  private static final BigInteger SN_ON_HOLD = BigInteger.valueOf(0x1003);

  private static final BigInteger SN_EXPIRED = BigInteger.valueOf(0x1004);

  private static final BigInteger SN_NOT_YET_VALID = BigInteger.valueOf(0x1005);

  private static final BigInteger SN_UNKNOWN = BigInteger.valueOf(0x1999);

  private static final BigInteger SN_OF_REVOKED_CA = BigInteger.valueOf(0x2001);

  private static final BigInteger SN_OF_NON_X509_CA = BigInteger.valueOf(0x3001);

  private static final BigInteger SN_OF_CA_WITHOUT_REV_DATE = BigInteger.valueOf(0x4001);

  private static final BigInteger SN_OF_CA_WITH_NULL_REV_DATE = BigInteger.valueOf(0x5001);

  private static final Instant REVOCATION_TIME =
      Instant.now().minus(2, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);

  private static final Instant CA_REVOCATION_TIME =
      Instant.now().minus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS);

  private static Path workDir;

  private static DataSourceWrapper datasource;

  private static Securities securities;

  private static OcspServer server;

  private static Responder responder;

  /** X.509 CA, not revoked. */
  private static X509Cert ca1Cert;

  /** X.509 CA, revoked. */
  private static X509Cert ca2Cert;

  /** CA with the type other than X.509 (catype 2), must be ignored by the store. */
  private static X509Cert ca3Cert;

  /** X.509 CA, revoked, without the revocation date in the CA data. */
  private static X509Cert ca4Cert;

  /** X.509 CA, revoked, with the revocation date null in the CA data. */
  private static X509Cert ca5Cert;

  /** Start of {@link #init()}. */
  private static Instant initTime;

  @BeforeClass
  public static void init() throws Exception {
    initTime = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    workDir = Files.createTempDirectory("xipki-ocsp-ejbca-test");
    Passwords.init(workDir.toString());
    Audits.init("noop", new ConfPairs(), workDir.toString());

    Path dbConf = writeDbConf("ejbca_" + UUID.randomUUID().toString().replace("-", ""));
    datasource = createDatasource(dbConf);

    ca1Cert = newCaCert();
    ca2Cert = newCaCert();
    ca3Cert = newCaCert();
    ca4Cert = newCaCert();
    ca5Cert = newCaCert();

    Instant now = Instant.now();
    Instant notBefore = now.minus(30, ChronoUnit.DAYS);
    Instant notAfter = now.plus(30, ChronoUnit.DAYS);
    try (Connection conn = datasource.getConnection()) {
      String schema;
      try (InputStream in = OcspEjbcaStoreH2Test.class.getResourceAsStream(SCHEMA)) {
        Assert.assertNotNull(SCHEMA, in);
        schema = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      }
      for (String sql : schema.replaceAll("(?m)^--.*$", "").split(";")) {
        if (!sql.isBlank()) {
          exec(conn, sql);
        }
      }

      addCa(conn, 1, "ca1", 1, ca1Cert, null);
      addCa(conn, 2, "ca2", 1, ca2Cert, CA_REVOCATION_TIME);
      addCa(conn, 3, "ca3", 2, ca3Cert, null);
      addCa(conn, 4, "ca4", 1, ca4Cert, true, false, null);
      addCa(conn, 5, "ca5", 1, ca5Cert, true, true, null);

      addCert(conn, ca1Cert, SN_GOOD, notBefore, notAfter, null, null);
      addCert(conn, ca1Cert, SN_REVOKED, notBefore, notAfter,
          CrlReason.KEY_COMPROMISE, REVOCATION_TIME);
      addCert(conn, ca1Cert, SN_ON_HOLD, notBefore, notAfter,
          CrlReason.CERTIFICATE_HOLD, REVOCATION_TIME);
      addCert(conn, ca1Cert, SN_EXPIRED, notBefore, now.minus(1, ChronoUnit.DAYS), null, null);
      addCert(conn, ca1Cert, SN_NOT_YET_VALID, now.plus(1, ChronoUnit.DAYS), notAfter,
          null, null);
      addCert(conn, ca2Cert, SN_OF_REVOKED_CA, notBefore, notAfter, null, null);
      addCert(conn, ca3Cert, SN_OF_NON_X509_CA, notBefore, notAfter, null, null);
      addCert(conn, ca4Cert, SN_OF_CA_WITHOUT_REV_DATE, notBefore, notAfter, null, null);
      addCert(conn, ca5Cert, SN_OF_CA_WITH_NULL_REV_DATE, notBefore, notAfter, null, null);
    }

    securities = new Securities();
    securities.init(null, workDir.toString());

    server = new OcspServer(workDir.toString());
    server.setSecurityFactory(securities.securityFactory());
    server.setConfFile(OcspTestUtil.writeResponderConf(workDir, dbConf,
        "{\"datasource\": \"ocspdb\", \"type\": \"ejbca-db\", \"conf\": {}}",
        "unknown", "").toString());
    server.init(true);
    responder = server.getResponder("responder1");
    Assert.assertNotNull("responder1", responder);
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
    // the serial number is longer than a long: stored in decimal
    Assert.assertEquals(OcspCertStatus.GOOD, status(ca1Cert, SN_GOOD));
  }

  @Test
  public void revokedCertificate() throws Exception {
    OcspCertStatus status = status(ca1Cert, SN_REVOKED);
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.keyCompromise, status.getRevoked().getRevocationReason());
    Assert.assertEquals(REVOCATION_TIME, status.getRevoked().getRevocationTime().getTime());
  }

  @Test
  public void certificateOnHold() throws Exception {
    OcspCertStatus status = status(ca1Cert, SN_ON_HOLD);
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.certificateHold, status.getRevoked().getRevocationReason());
    Assert.assertEquals(REVOCATION_TIME, status.getRevoked().getRevocationTime().getTime());
  }

  @Test
  public void unknownSerialNumber() throws Exception {
    OcspTestUtil.assertNonIssued(status(ca1Cert, SN_UNKNOWN));
  }

  @Test
  public void serialNumberOfOtherCaIsUnknown() throws Exception {
    OcspTestUtil.assertNonIssued(status(ca1Cert, SN_OF_REVOKED_CA));
  }

  @Test
  public void expiredCertificateIsIgnored() throws Exception {
    // ignoreExpiredCert = true
    OcspTestUtil.assertNonIssued(status(ca1Cert, SN_EXPIRED));
  }

  @Test
  public void notYetValidCertificateIsIgnored() throws Exception {
    // ignoreNotYetValidCert = true
    OcspTestUtil.assertNonIssued(status(ca1Cert, SN_NOT_YET_VALID));
  }

  @Test
  public void revocationOfCaIsInherited() throws Exception {
    // inheritCaRevocation = true
    OcspCertStatus status = status(ca2Cert, SN_OF_REVOKED_CA);
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.cACompromise, status.getRevoked().getRevocationReason());
    Assert.assertEquals(CA_REVOCATION_TIME.truncatedTo(ChronoUnit.SECONDS),
        status.getRevoked().getRevocationTime().getTime());
  }

  @Test
  public void revokedCaWithoutRevocationDate() throws Exception {
    // revokationreason set, revokationdate absent: the store uses the current time
    assertCaRevokedNow(ca4Cert, SN_OF_CA_WITHOUT_REV_DATE);
  }

  @Test
  public void revokedCaWithNullRevocationDate() throws Exception {
    // revokationreason set, revokationdate <null/>: as absent, not a <long> of another key
    // (here the expiretime, the notAfter of the CA certificate)
    assertCaRevokedNow(ca5Cert, SN_OF_CA_WITH_NULL_REV_DATE);
  }

  @Test
  public void nonX509CaIsUnknownIssuer() throws Exception {
    // unknownIssuerBehaviour = malformedRequest
    OCSPResponse resp = OCSPResponse.fromEncoded(server.answer(responder,
        OcspTestUtil.request(OcspTestUtil.certId(ca3Cert, SN_OF_NON_X509_CA)), false).response());
    Assert.assertEquals(OCSPResponseStatus.MALFORMED_REQUEST, resp.getResponseStatus());
  }

  @Test
  public void healthCheck() {
    Assert.assertTrue(server.healthCheck(responder));
  }

  // ----- helpers -----

  /** The CA is revoked (cACompromise) at the time the store has read the CA data. */
  private static void assertCaRevokedNow(X509Cert caCert, BigInteger serial) throws Exception {
    OcspCertStatus status = status(caCert, serial);
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.cACompromise, status.getRevoked().getRevocationReason());
    Instant revTime = status.getRevoked().getRevocationTime().getTime();
    Assert.assertFalse("revocation time " + revTime + " before the start " + initTime,
        revTime.isBefore(initTime));
    Assert.assertFalse("revocation time " + revTime + " in the future",
        revTime.isAfter(Instant.now()));
  }

  private static OcspCertStatus status(X509Cert issuer, BigInteger serial) throws Exception {
    return OcspTestUtil.status(server, responder, issuer, serial);
  }

  /** The SHA-1 fingerprint in lower-case hex, as CertTools.getFingerprintAsString of EJBCA. */
  private static String fingerprint(byte[] encoded) {
    return Hex.encode(HashAlgo.SHA1.hash(encoded)).toLowerCase(Locale.ROOT);
  }

  /**
   * The column {@code data} of {@code CAData}, as written by EJBCA CE: the data map of the CA
   * (a {@code LinkedHashMap}) encoded by {@code java.beans.XMLEncoder}
   * (CAData.setDataMap). The values have the types of CABaseCommon: {@code catype} Integer
   * (CAInfo.CATYPE_X509 = 1), {@code certificatechain} ArrayList of Base64 strings in lines of
   * 64 characters (com.keyfactor.util.Base64.encode(byte[])), {@code revokationreason}
   * Integer (-1 if not revoked) and {@code revokationdate} java.util.Date (absent if not
   * revoked).
   */
  private static String caData(int caType, X509Cert cert, boolean revoked, boolean nullDate,
                               Instant revocationTime) throws Exception {
    Map<Object, Object> data = new LinkedHashMap<>();
    data.put("version", 24.0f);
    data.put("catype", caType);
    data.put("subjectdn", cert.subjectText());
    data.put("certificatechain", new ArrayList<>(List.of(ejbcaBase64(cert.getEncoded()))));
    data.put("revokationreason", revoked ? CrlReason.CA_COMPROMISE.code() : NOT_REVOKED);
    if (revocationTime != null || nullDate) {
      data.put("revokationdate", revocationTime == null ? null : Date.from(revocationTime));
    }
    data.put("expiretime", Date.from(cert.notAfter()));

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (XMLEncoder encoder = new XMLEncoder(out)) {
      encoder.writeObject(data);
    }
    return out.toString(StandardCharsets.UTF_8);
  }

  /** As com.keyfactor.util.Base64.encode(byte[]): lines of 64 characters, separated by LF. */
  private static String ejbcaBase64(byte[] data) {
    String b64 = Base64.encodeToString(data);
    StringBuilder sb = new StringBuilder(b64.length() + b64.length() / 64);
    for (int i = 0; i < b64.length(); i += 64) {
      if (i > 0) {
        sb.append('\n');
      }
      sb.append(b64, i, Math.min(i + 64, b64.length()));
    }
    return sb.toString();
  }

  private static void addCa(Connection conn, int id, String name, int caType, X509Cert cert,
                            Instant revocationTime) throws Exception {
    addCa(conn, id, name, caType, cert, revocationTime != null, false, revocationTime);
  }

  /**
   * @param nullDate whether {@code revokationdate} is written as {@code <null/>} if
   *        {@code revocationTime} is {@code null} (otherwise absent).
   */
  private static void addCa(Connection conn, int id, String name, int caType, X509Cert cert,
                            boolean revoked, boolean nullDate, Instant revocationTime)
      throws Exception {
    try (PreparedStatement ps = conn.prepareStatement("INSERT INTO CAData "
        + "(cAId,data,expireTime,name,rowVersion,status,subjectDN,updateTime) "
        + "VALUES (?,?,?,?,0,?,?,?)")) {
      int idx = 1;
      ps.setInt(idx++, id);
      ps.setString(idx++, caData(caType, cert, revoked, nullDate, revocationTime));
      ps.setLong(idx++, cert.notAfter().toEpochMilli());
      ps.setString(idx++, name);
      // EJBCA: CAConstants.CA_ACTIVE = 1, CA_REVOKED = 3
      ps.setInt(idx++, revoked ? 3 : 1);
      ps.setString(idx++, cert.subjectText());
      ps.setLong(idx, System.currentTimeMillis());
      ps.executeUpdate();
    }
  }

  private static void addCert(Connection conn, X509Cert caCert, BigInteger serial,
                              Instant notBefore, Instant notAfter, CrlReason reason,
                              Instant revocationTime) throws Exception {
    // the certificate itself is not read by the store: a unique placeholder for the fingerprint
    byte[] placeholder = (fingerprint(caCert.getEncoded()) + serial).getBytes();
    try (PreparedStatement ps = conn.prepareStatement("INSERT INTO CertificateData "
        + "(fingerprint,cAFingerprint,certificateProfileId,expireDate,issuerDN,notBefore,"
        + "revocationDate,revocationReason,rowVersion,serialNumber,status,subjectDN,type,"
        + "updateTime) VALUES (?,?,1,?,?,?,?,?,0,?,?,?,?,?)")) {
      int idx = 1;
      ps.setString(idx++, fingerprint(placeholder));
      ps.setString(idx++, fingerprint(caCert.getEncoded()));
      ps.setLong(idx++, notAfter.toEpochMilli());
      ps.setString(idx++, caCert.subjectText());
      ps.setLong(idx++, notBefore.toEpochMilli());
      ps.setLong(idx++, revocationTime == null ? -1 : revocationTime.toEpochMilli());
      ps.setInt(idx++, reason == null ? NOT_REVOKED : reason.code());
      ps.setString(idx++, serial.toString());
      ps.setInt(idx++, reason == null ? CERT_ACTIVE : CERT_REVOKED);
      ps.setString(idx++, "CN=ee-" + serial);
      ps.setInt(idx++, CERTTYPE_ENDENTITY);
      ps.setLong(idx, System.currentTimeMillis());
      ps.executeUpdate();
    }
  }

  private static void exec(Connection conn, String sql) throws Exception {
    try (PreparedStatement ps = conn.prepareStatement(sql)) {
      ps.executeUpdate();
    }
  }

  private static X509Cert newCaCert() throws Exception {
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(PASSWORD.toCharArray())).keystore();
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, PASSWORD.toCharArray(), null,
          PASSWORD.toCharArray(), (X509Cert) null).certChain()[0];
    }
  }

  private static Path writeDbConf(String dbName) throws Exception {
    String conf = "dataSourceClassName = org.h2.jdbcx.JdbcDataSource\n"
        + "dataSource.url = jdbc:h2:mem:" + dbName + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1\n"
        + "dataSource.user = sa\n"
        + "dataSource.password = \n"
        + "autoCommit = true\n"
        + "maximumPoolSize = 5\n"
        + "minimumIdle = 1\n";
    Path file = workDir.resolve("ejbca-db.properties");
    Files.writeString(file, conf);
    return file;
  }

  private static DataSourceWrapper createDatasource(Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return new DataSourceFactory().createDataSource("ejbca-test", props);
  }

}
