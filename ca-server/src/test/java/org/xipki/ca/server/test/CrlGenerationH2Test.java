// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x509.CRLEntry;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.KeyCertBytesPair;
import org.xipki.pkix.cert.X509Crl;
import org.xipki.pkix.util.X509Util;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

/**
 * Integration test of the CRL generation on in-memory H2 databases.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlGenerationH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

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
  public void crlIsSignedByCa() throws Exception {
    X509Crl crl = caManager.generateCrlOnDemand(CA);
    Assert.assertEquals(env.caCert().subject(), crl.issuer());
    Assert.assertTrue(crl.thisUpdate().isBefore(crl.nextUpdate()));

    CertificateList asn1 = CertificateList.fromEncoded(crl.getEncoded());
    Assert.assertTrue("CRL signature",
        asn1.isSignatureValid(env.securities().securityFactory()
            .getContentVerifierFactory(env.caCert())));
  }

  @Test
  public void crlContainsExactlyTheRevokedCertificates() throws Exception {
    BigInteger good = issue("good.example.org");
    BigInteger revoked = issue("revoked.example.org");
    BigInteger onHold = issue("onhold.example.org");
    caManager.revokeCertificate(CA, revoked, CrlReason.KEY_COMPROMISE, null);
    caManager.revokeCertificate(CA, onHold, CrlReason.CERTIFICATE_HOLD, null);

    Set<BigInteger> serials = revokedSerials(caManager.generateCrlOnDemand(CA));
    Assert.assertTrue(serials.contains(revoked));
    Assert.assertTrue(serials.contains(onHold));
    Assert.assertFalse(serials.contains(good));

    // an unsuspended certificate is no longer in the next full CRL
    caManager.unsuspendCertificate(CA, onHold);
    serials = revokedSerials(caManager.generateCrlOnDemand(CA));
    Assert.assertTrue(serials.contains(revoked));
    Assert.assertFalse(serials.contains(onHold));
  }

  @Test
  public void crlNumberIncreasesAndCrlsAreStored() throws Exception {
    X509Crl crl1 = caManager.generateCrlOnDemand(CA);
    X509Crl crl2 = caManager.generateCrlOnDemand(CA);
    Assert.assertTrue("CRL number must increase",
        crl2.crlNumber().compareTo(crl1.crlNumber()) > 0);

    Assert.assertArrayEquals(crl2.getEncoded(), caManager.getCurrentCrl(CA).getEncoded());
    Assert.assertArrayEquals(crl1.getEncoded(),
        caManager.getCrl(CA, crl1.crlNumber().longValueExact()).getEncoded());
  }

  private static BigInteger issue(String commonName) throws Exception {
    KeyCertBytesPair keyCert = caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null);
    return X509Util.parseCert(keyCert.cert()).serialNumber();
  }

  private static Set<BigInteger> revokedSerials(X509Crl crl) throws Exception {
    Set<BigInteger> serials = new HashSet<>();
    for (CRLEntry entry : CertificateList.fromEncoded(crl.getEncoded())
        .getRevokedCertificates()) {
      serials.add(entry.getUserCertificate().getValue());
    }
    return serials;
  }

}
