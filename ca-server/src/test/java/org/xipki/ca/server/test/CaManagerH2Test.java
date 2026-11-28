// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.KeyCertBytesPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;

import java.math.BigInteger;

/**
 * Integration test of {@link CaManagerImpl} on in-memory H2 databases: CA setup, certificate
 * issuance and the certificate life cycle.
 *
 * @author Lijun Liao (xipki)
 */
public class CaManagerH2Test {

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    caManager = env.caManager();
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void caSystemIsStarted() {
    Assert.assertEquals(CaSystemStatus.STARTED_AS_MASTER, caManager.getCaSystemStatus());
    Assert.assertTrue(caManager.getSuccessfulCaNames().contains(CaH2TestEnv.CA_NAME));
    Assert.assertTrue(caManager.getFailedCaNames().isEmpty());
  }

  @Test
  public void rootCaIsSelfSigned() throws Exception {
    X509Cert caCert = env.caCert();
    Assert.assertEquals(caCert.subject(), caCert.issuer());
    caCert.verify(caCert.publicKey());
    Assert.assertEquals(CertVariant.ofX509(caCert),
        caManager.getCaCerts(CaH2TestEnv.CA_NAME).get(0));
  }

  @Test
  public void issueCertificate() throws Exception {
    X509Cert cert = issue("issue.example.org");
    Assert.assertEquals(env.caCert().subject(), cert.issuer());
    cert.verify(env.caCert().publicKey());

    CertWithRevocationInfo stored = caManager.getCert(CaH2TestEnv.CA_NAME, cert.serialNumber());
    Assert.assertNotNull(stored);
    Assert.assertFalse(stored.isRevoked());
    Assert.assertEquals(cert, stored.cert().x509Cert());
    Assert.assertEquals(CaH2TestEnv.PROFILE_TLS, stored.certprofile());
  }

  @Test
  public void revokeAndUnsuspend() throws Exception {
    BigInteger serial = issue("hold.example.org").serialNumber();

    caManager.revokeCertificate(CaH2TestEnv.CA_NAME, serial, CrlReason.CERTIFICATE_HOLD, null);
    CertWithRevocationInfo info = caManager.getCert(CaH2TestEnv.CA_NAME, serial);
    Assert.assertTrue(info.isRevoked());
    Assert.assertEquals(CrlReason.CERTIFICATE_HOLD, info.revInfo().reason());

    caManager.unsuspendCertificate(CaH2TestEnv.CA_NAME, serial);
    Assert.assertFalse(caManager.getCert(CaH2TestEnv.CA_NAME, serial).isRevoked());

    caManager.revokeCertificate(CaH2TestEnv.CA_NAME, serial, CrlReason.KEY_COMPROMISE, null);
    info = caManager.getCert(CaH2TestEnv.CA_NAME, serial);
    Assert.assertTrue(info.isRevoked());
    Assert.assertEquals(CrlReason.KEY_COMPROMISE, info.revInfo().reason());

    // a permanently revoked certificate cannot be unsuspended
    Assert.assertThrows(CaMgmtException.class,
        () -> caManager.unsuspendCertificate(CaH2TestEnv.CA_NAME, serial));
  }

  @Test
  public void removeCertificate() throws Exception {
    BigInteger serial = issue("remove.example.org").serialNumber();
    caManager.removeCertificate(CaH2TestEnv.CA_NAME, serial);
    Assert.assertNull(caManager.getCert(CaH2TestEnv.CA_NAME, serial));
  }

  @Test
  public void unknownProfileIsRejected() {
    Assert.assertThrows(CaMgmtException.class, () -> caManager.generateKeyCert(
        CaH2TestEnv.CA_NAME, "unknown", "CN=x.example.org", null, null));
  }

  private static X509Cert issue(String commonName) throws Exception {
    KeyCertBytesPair keyCert = caManager.generateKeyCert(CaH2TestEnv.CA_NAME,
        CaH2TestEnv.PROFILE_TLS, "CN=" + commonName + ",O=myorg,C=DE", null, null);
    return X509Util.parseCert(keyCert.cert());
  }

}
