// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.ca.sdk.ErrorCode;
import org.xipki.ca.sdk.OperationException;
import org.xipki.ca.server.Ca;
import org.xipki.ca.server.CertTemplateData;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.CertRevocationInfo;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.X509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.audit.AuditStatus;
import org.xipki.util.misc.NameId;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Integration test of the certificate issuance rules of the CA (notBefore / notAfter,
 * public key checks, revoked CA) on in-memory H2 databases.
 *
 * @author Lijun Liao (xipki)
 */
public class CaIssuanceH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static final BigInteger RSA_E = BigInteger.valueOf(65537);

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  private static Ca ca;

  private static RequestorInfo requestor;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    caManager = env.caManager();
    ca = caManager.getCaInstance(CA);
    NameId byCa = caManager.idNameMap().getRequestor(RequestorInfo.NAME_BY_CA);
    Assert.assertNotNull("requestor " + RequestorInfo.NAME_BY_CA, byCa);
    requestor = new RequestorInfo.ByCaRequestorInfo(byCa);
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void issueFromCsr() throws Exception {
    X509KeyPairWithSubjectPublicKeyInfo kp = KeyUtil.generateX509KeyPair2(KeySpec.P256);
    X509Cert cert = caManager.generateCertificate(CA, CaH2TestEnv.PROFILE_TLS,
        csr("csr.example.org", kp), null, null);

    cert.verify(env.caCert().publicKey());
    Assert.assertEquals(kp.subjectPublicKeyInfo(), cert.subjectPublicKeyInfo());
    Assert.assertEquals(env.caCert().subject(), cert.issuer());
  }

  @Test
  public void csrWithInvalidSignatureIsRejected() throws Exception {
    X509KeyPairWithSubjectPublicKeyInfo kp = KeyUtil.generateX509KeyPair2(KeySpec.P256);
    X509KeyPairWithSubjectPublicKeyInfo other = KeyUtil.generateX509KeyPair2(KeySpec.P256);
    // the CSR contains the public key of kp, but is signed with the key of other
    byte[] csr = new CertificationRequest.CsrBuilder(
        new X500Name("CN=pop.example.org,O=myorg,C=DE"), kp.subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(other.keypair().getPrivate(), other.keypair().getPublic())
            .contentSigner())
        .getEncoded();

    Assert.assertThrows(CaMgmtException.class, () -> caManager.generateCertificate(
        CA, CaH2TestEnv.PROFILE_TLS, csr, null, null));
  }

  @Test
  public void requestedShortValidityIsKept() throws Exception {
    Instant notAfter = CaH2TestEnv.inDays(30);
    X509Cert cert = generate("short.example.org", newP256Key(), null, notAfter);
    Assert.assertEquals(notAfter, cert.notAfter());
  }

  @Test
  public void validityIsLimitedByTheProfile() throws Exception {
    // the profile tls-ec allows 5 years, the CA 10 years
    X509Cert cert = generate("long.example.org", newP256Key(), null, CaH2TestEnv.inDays(20 * 365));
    Instant maxNotAfter = cert.notBefore().atZone(ZoneOffset.UTC).plusYears(5)
        .toInstant();
    Assert.assertFalse("notAfter after notBefore + 5y", cert.notAfter().isAfter(maxNotAfter));
    Assert.assertTrue("notAfter before notBefore + 5y - 1d",
        cert.notAfter().isAfter(maxNotAfter.minus(1, ChronoUnit.DAYS)));
  }

  @Test
  public void notBeforeInThePastIsCorrected() throws Exception {
    Instant start = Instant.now();
    X509Cert cert = generate("past.example.org", newP256Key(), CaH2TestEnv.inDays(-30), null);
    // at most 10 minutes in the past are allowed
    Assert.assertFalse("notBefore too early",
        cert.notBefore().isBefore(start.minus(Duration.ofMinutes(10)).minusSeconds(1)));
    Assert.assertFalse("notBefore before the CA's notBefore",
        cert.notBefore().isBefore(env.caCert().notBefore()));
  }

  @Test
  public void keyAlgorithmNotAllowedByProfile() throws Exception {
    SubjectPublicKeyInfo rsaKey = KeyUtil.generateX509KeyPair2(KeySpec.RSA2048)
        .subjectPublicKeyInfo();
    OperationException ex = Assert.assertThrows(OperationException.class,
        () -> generate("rsa.example.org", rsaKey, null, null));
    Assert.assertEquals(ErrorCode.BAD_CERT_TEMPLATE, ex.errorCode());
    Assert.assertFalse(messages(ex).contains("too weak"));
  }

  @Test
  public void rocaAffectedRsaKeyIsRejected() throws Exception {
    // A modulus which is a power of 65537 has the fingerprint of the keys affected by
    // ROCA (CVE-2017-15361): modulo each small prime, it is in the group generated by 65537.
    SubjectPublicKeyInfo weakKey = rsaKey(RSA_E.pow(130));
    OperationException ex = Assert.assertThrows(OperationException.class,
        () -> generate("roca.example.org", weakKey, null, null));
    Assert.assertEquals(ErrorCode.BAD_CERT_TEMPLATE, ex.errorCode());
    Assert.assertTrue(messages(ex), messages(ex).contains("RSA public key is too weak"));
  }

  @Test
  public void unknownProfileIsRejected() {
    OperationException ex = Assert.assertThrows(OperationException.class,
        () -> ca.generateCert(requestor, new CertTemplateData(
            new X500Name("CN=x.example.org"), newP256Key(), null, null, null, "unknown"), null));
    Assert.assertEquals(ErrorCode.UNKNOWN_CERT_PROFILE, ex.errorCode());
  }

  @Test
  public void subjectNotPermittedByProfile() {
    // the profile requires the commonName to be an FQDN
    OperationException ex = Assert.assertThrows(OperationException.class,
        () -> generate("not a domain", newP256Key(), null, null));
    Assert.assertEquals(ErrorCode.BAD_CERT_TEMPLATE, ex.errorCode());
  }

  @Test
  public void revokedCaDoesNotIssue() throws Exception {
    caManager.revokeCa(CA, new CertRevocationInfo(CrlReason.CERTIFICATE_HOLD));
    try {
      // the revocation is saved: it is still there after reloading the CA from the database
      caManager.restartCa(CA);
      ca = caManager.getCaInstance(CA);
      Assert.assertEquals(CrlReason.CERTIFICATE_HOLD,
          caManager.getCa(CA).base().revocationInfo().reason());

      OperationException ex = Assert.assertThrows(OperationException.class,
          () -> generate("revokedca.example.org", newP256Key(), null, null));
      Assert.assertEquals(ErrorCode.NOT_PERMITTED, ex.errorCode());
    } finally {
      caManager.unrevokeCa(CA);
    }

    caManager.restartCa(CA);
    ca = caManager.getCaInstance(CA);
    Assert.assertNull(caManager.getCa(CA).base().revocationInfo());

    // issuance works again after unrevoking
    generate("unrevokedca.example.org", newP256Key(), null, null);
  }

  @Test
  public void caRevocationIsAudited() throws Exception {
    RecordingAuditService.install();
    try {
      try {
        caManager.revokeCa(CA, new CertRevocationInfo(CrlReason.CERTIFICATE_HOLD));
      } finally {
        caManager.unrevokeCa(CA);
      }

      try {
        caManager.revokeCa(CA, new CertRevocationInfo(CrlReason.KEY_COMPROMISE));
      } finally {
        caManager.unrevokeCa(CA);
      }

      assertAudited(CaAuditConstants.TYPE_suspend_ca, 1, "certificateHold");
      assertAudited(CaAuditConstants.TYPE_revoke_ca, 1, "keyCompromise");
      assertAudited(CaAuditConstants.TYPE_unsuspend_ca, 2, null);
    } finally {
      RecordingAuditService.uninstall();
    }
  }

  private static void assertAudited(String eventType, int expectedCount, String expectedReason) {
    List<AuditEvent> events = RecordingAuditService.events(eventType);
    Assert.assertEquals("number of events " + eventType, expectedCount, events.size());
    for (AuditEvent event : events) {
      Assert.assertEquals(eventType + " status", AuditStatus.SUCCESSFUL, event.status());
      Assert.assertEquals(eventType + " CA serial", "0x01",
          RecordingAuditService.eventData(event, CaAuditConstants.NAME_serial));
      if (expectedReason != null) {
        Assert.assertEquals(eventType + " reason", expectedReason,
            RecordingAuditService.eventData(event, CaAuditConstants.NAME_reason));
      }
    }
  }

  private static X509Cert generate(String commonName, SubjectPublicKeyInfo publicKey,
                                   Instant notBefore, Instant notAfter)
      throws OperationException {
    CertTemplateData template = new CertTemplateData(
        new X500Name("CN=" + commonName + ",O=myorg,C=DE"), publicKey, notBefore, notAfter,
        null, CaH2TestEnv.PROFILE_TLS);
    CertificateInfo certInfo = ca.generateCert(requestor, template, null);
    return certInfo.cert().cert();
  }

  private static SubjectPublicKeyInfo newP256Key() {
    try {
      return KeyUtil.generateX509KeyPair2(KeySpec.P256).subjectPublicKeyInfo();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static SubjectPublicKeyInfo rsaKey(BigInteger modulus) throws Exception {
    PublicKey key = KeyFactory.getInstance("RSA").generatePublic(
        new RSAPublicKeySpec(modulus, RSA_E));
    return KeyUtil.createX509SubjectPublicKeyInfo(key);
  }

  private static byte[] csr(String commonName, X509KeyPairWithSubjectPublicKeyInfo kp)
      throws Exception {
    return new CertificationRequest.CsrBuilder(
        new X500Name("CN=" + commonName + ",O=myorg,C=DE"), kp.subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(kp.keypair().getPrivate(), kp.keypair().getPublic())
            .contentSigner())
        .getEncoded();
  }

  /** All messages of the exception and its causes. */
  private static String messages(Throwable ex) {
    StringBuilder sb = new StringBuilder();
    for (Throwable t = ex; t != null; t = t.getCause()) {
      sb.append(t.getMessage()).append("; ");
    }
    return sb.toString();
  }

}
