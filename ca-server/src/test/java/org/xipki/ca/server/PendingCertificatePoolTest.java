// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.misc.NameId;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Set;

/**
 * Unit test of {@link PendingCertificatePool}.
 *
 * @author Lijun Liao (xipki)
 */
public class PendingCertificatePoolTest {

  private static X509Cert cert1;

  private static X509Cert cert2;

  @BeforeClass
  public static void init() throws Exception {
    cert1 = newCert();
    cert2 = newCert();
  }

  @Test
  public void confirmWithMatchingHash() {
    PendingCertificatePool pool = new PendingCertificatePool();
    CertificateInfo info = certInfo(cert1);
    pool.addCertificate("tid1", BigInteger.ONE, info, future());

    Assert.assertSame(info, pool.removeCertificate("tid1", BigInteger.ONE, sha1(cert1)));
    // already removed
    Assert.assertNull(pool.removeCertificate("tid1", BigInteger.ONE, sha1(cert1)));
    Assert.assertNull(pool.removeCertificates("tid1"));
  }

  @Test
  public void hashMismatchDoesNotRemove() {
    PendingCertificatePool pool = new PendingCertificatePool();
    CertificateInfo info = certInfo(cert1);
    pool.addCertificate("tid1", BigInteger.ONE, info, future());

    // the entry is returned, but stays in the pool since the hash does not match
    Assert.assertSame(info, pool.removeCertificate("tid1", BigInteger.ONE, sha1(cert2)));
    Assert.assertSame(info, pool.removeCertificate("tid1", BigInteger.ONE, sha1(cert1)));
  }

  @Test
  public void unknownTransactionOrRequestId() {
    PendingCertificatePool pool = new PendingCertificatePool();
    pool.addCertificate("tid1", BigInteger.ONE, certInfo(cert1), future());

    Assert.assertNull(pool.removeCertificate("tid2", BigInteger.ONE, sha1(cert1)));
    Assert.assertNull(pool.removeCertificate("tid1", BigInteger.TWO, sha1(cert1)));
    Assert.assertNull(pool.removeCertificates("tid2"));
  }

  @Test
  public void removeAllOfATransaction() {
    PendingCertificatePool pool = new PendingCertificatePool();
    CertificateInfo info1 = certInfo(cert1);
    CertificateInfo info2 = certInfo(cert2);
    CertificateInfo other = certInfo(cert1);
    pool.addCertificate("tid1", BigInteger.ONE, info1, future());
    pool.addCertificate("tid1", BigInteger.TWO, info2, future());
    pool.addCertificate("tid2", BigInteger.ONE, other, future());

    Set<CertificateInfo> removed = pool.removeCertificates("tid1");
    Assert.assertEquals(Set.of(info1, info2), removed);
    Assert.assertNull(pool.removeCertificates("tid1"));
    Assert.assertSame(other, pool.removeCertificate("tid2", BigInteger.ONE, sha1(cert1)));
  }

  @Test
  public void alreadyIssuedCertificatesAreNotPooled() {
    PendingCertificatePool pool = new PendingCertificatePool();
    CertificateInfo info = certInfo(cert1);
    info.setAlreadyIssued(true);
    pool.addCertificate("tid1", BigInteger.ONE, info, future());
    Assert.assertNull(pool.removeCertificates("tid1"));
  }

  @Test
  public void timeoutedCertificatesAreRemoved() {
    PendingCertificatePool pool = new PendingCertificatePool();
    Assert.assertNull("empty pool", pool.removeConfirmTimeoutedCertificates());

    CertificateInfo expired1 = certInfo(cert1);
    CertificateInfo expired2 = certInfo(cert2);
    CertificateInfo pending = certInfo(cert2);
    long past = System.currentTimeMillis() - 1000;
    pool.addCertificate("tid1", BigInteger.ONE, expired1, past);
    pool.addCertificate("tid1", BigInteger.TWO, pending, future());
    pool.addCertificate("tid2", BigInteger.ONE, expired2, past);

    Assert.assertEquals(Set.of(expired1, expired2), pool.removeConfirmTimeoutedCertificates());
    // tid2 has no more entries, tid1 keeps the pending one
    Assert.assertNull(pool.removeCertificates("tid2"));
    Assert.assertEquals(Set.of(pending), pool.removeCertificates("tid1"));
    Assert.assertNull("empty pool", pool.removeConfirmTimeoutedCertificates());
  }

  @Test
  public void invalidArguments() {
    PendingCertificatePool pool = new PendingCertificatePool();
    Assert.assertThrows(RuntimeException.class,
        () -> pool.addCertificate(null, BigInteger.ONE, certInfo(cert1), future()));
    Assert.assertThrows(RuntimeException.class,
        () -> pool.addCertificate("tid", null, certInfo(cert1), future()));
    Assert.assertThrows(RuntimeException.class,
        () -> pool.removeCertificate("", BigInteger.ONE, new byte[20]));
  }

  private static long future() {
    return System.currentTimeMillis() + 60_000;
  }

  private static byte[] sha1(X509Cert cert) {
    return HashAlgo.SHA1.hash(cert.getEncoded());
  }

  private static CertificateInfo certInfo(X509Cert cert) {
    return new CertificateInfo(new CertWithDbId(cert), null, new NameId(1, "ca"), cert,
        new NameId(2, "profile"), new NameId(3, "requestor"));
  }

  private static X509Cert newCert() throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, password, null, password,
          (X509Cert) null).certChain()[0];
    }
  }

}
