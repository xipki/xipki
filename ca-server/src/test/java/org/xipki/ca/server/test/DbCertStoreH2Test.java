// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.server.CaIdNameMap;
import org.xipki.ca.server.CertRevInfoWithSerial;
import org.xipki.ca.server.CertStore.CertStatus;
import org.xipki.ca.server.CertStore.SerialWithId;
import org.xipki.ca.server.db.DbCaConfStore;
import org.xipki.ca.server.db.DbCertStore;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.KeyCertBytesPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.cert.X509Crl;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.misc.NameId;
import org.xipki.util.misc.UniqueIdGenerator;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Integration test of {@link DbCertStore} on in-memory H2 databases. The certificates are
 * issued by the CA system, and read back through a separate {@link DbCertStore} instance on
 * the same database.
 *
 * @author Lijun Liao (xipki)
 */
public class DbCertStoreH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  private static DbCertStore certstore;

  private static NameId caIdent;

  private static CaIdNameMap idNameMap;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    caManager = env.caManager();
    idNameMap = caManager.idNameMap();
    caIdent = idNameMap.getCa(CA);
    // shard id 1: must differ from the one of the CA system (0) on the same database
    certstore = new DbCertStore(env.caDatasource(),
        new DbCaConfStore(env.caconfDatasource()), new UniqueIdGenerator(0, 1));
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void certIsFoundBySerialAndId() throws Exception {
    X509Cert cert = issue("lookup.example.org");
    BigInteger serial = cert.serialNumber();

    long id = certstore.getCertId(caIdent, serial);
    Assert.assertTrue(id > 0);

    CertWithRevocationInfo bySerial =
        certstore.getCertWithRevocationInfo(caIdent.id(), serial, idNameMap);
    Assert.assertEquals(cert, bySerial.cert().cert());
    Assert.assertEquals(id, (long) bySerial.cert().certId());
    Assert.assertEquals(CaH2TestEnv.PROFILE_TLS, bySerial.certprofile());

    CertWithRevocationInfo byId = certstore.getCertWithRevocationInfo(id, idNameMap);
    Assert.assertEquals(cert, byId.cert().cert());

    Assert.assertEquals(0, certstore.getCertId(caIdent, BigInteger.valueOf(Long.MAX_VALUE)));
  }

  @Test
  public void certStatusForSubject() throws Exception {
    X509Cert good = issue("status-good.example.org");
    X509Cert revoked = issue("status-revoked.example.org");
    caManager.revokeCertificate(CA, revoked.serialNumber(), CrlReason.SUPERSEDED, null);

    Assert.assertEquals(CertStatus.GOOD,
        certstore.getCertStatusForSubject(caIdent, good.subject()));
    Assert.assertEquals(CertStatus.REVOKED,
        certstore.getCertStatusForSubject(caIdent, revoked.subject()));
  }

  @Test
  public void countsAndSerialNumbers() throws Exception {
    long all = certstore.getCountOfCerts(caIdent, false);
    long revoked = certstore.getCountOfCerts(caIdent, true);

    X509Cert cert1 = issue("count1.example.org");
    X509Cert cert2 = issue("count2.example.org");
    caManager.revokeCertificate(CA, cert2.serialNumber(), CrlReason.CESSATION_OF_OPERATION, null);

    Assert.assertEquals(all + 2, certstore.getCountOfCerts(caIdent, false));
    Assert.assertEquals(revoked + 1, certstore.getCountOfCerts(caIdent, true));

    List<BigInteger> allSerials = serials(certstore.getSerialNumbers(caIdent, 0, 1000, false));
    Assert.assertTrue(allSerials.contains(cert1.serialNumber()));
    Assert.assertTrue(allSerials.contains(cert2.serialNumber()));

    List<BigInteger> revokedSerials =
        serials(certstore.getSerialNumbers(caIdent, 0, 1000, true));
    Assert.assertFalse(revokedSerials.contains(cert1.serialNumber()));
    Assert.assertTrue(revokedSerials.contains(cert2.serialNumber()));
  }

  @Test
  public void revokedAndSuspendedCerts() throws Exception {
    X509Cert revoked = issue("rev.example.org");
    X509Cert onHold = issue("hold2.example.org");
    caManager.revokeCertificate(CA, revoked.serialNumber(), CrlReason.KEY_COMPROMISE, null);
    caManager.revokeCertificate(CA, onHold.serialNumber(), CrlReason.CERTIFICATE_HOLD, null);

    CertRevInfoWithSerial revokedInfo = null;
    for (CertRevInfoWithSerial info : certstore.getRevokedCerts(caIdent, Instant.now(), 0, 1000)) {
      if (info.serial().equals(revoked.serialNumber())) {
        revokedInfo = info;
      }
    }
    Assert.assertNotNull(revokedInfo);
    Assert.assertEquals(CrlReason.KEY_COMPROMISE, revokedInfo.reason());

    List<BigInteger> suspended = serials(
        certstore.getSuspendedCertSerials(caIdent, Instant.now().plusSeconds(60), 1000));
    Assert.assertTrue(suspended.contains(onHold.serialNumber()));
    Assert.assertFalse(suspended.contains(revoked.serialNumber()));
  }

  @Test
  public void listCerts() throws Exception {
    X509Cert cert = issue("list.example.org");
    List<CertListInfo> list = certstore.listCerts(caIdent, null, null, null,
        CertListOrderBy.NOT_BEFORE_DESC, 1000);
    boolean found = false;
    for (CertListInfo info : list) {
      if (info.serialNumber().equals(cert.serialNumber())) {
        found = true;
        Assert.assertEquals(cert.notAfter(), info.notAfter());
      }
    }
    Assert.assertTrue("issued certificate is listed", found);
  }

  @Test
  public void removeCert() throws Exception {
    X509Cert cert = issue("rm.example.org");
    long id = certstore.getCertId(caIdent, cert.serialNumber());
    certstore.removeCert(id);
    Assert.assertEquals(0, certstore.getCertId(caIdent, cert.serialNumber()));
  }

  @Test
  public void crlsAreStoredAndCleanedUp() throws Exception {
    X509Crl crl1 = caManager.generateCrlOnDemand(CA);
    X509Crl crl2 = caManager.generateCrlOnDemand(CA);
    long crlNo2 = crl2.crlNumber().longValueExact();

    Assert.assertEquals(crlNo2, certstore.getMaxCrlNumber(caIdent));
    Assert.assertEquals(crlNo2, certstore.getMaxFullCrlNumber(caIdent));
    Assert.assertArrayEquals(crl1.getEncoded(),
        certstore.getEncodedCrl(caIdent, crl1.crlNumber().longValueExact()));
    // without CRL number: the latest one
    Assert.assertArrayEquals(crl2.getEncoded(), certstore.getEncodedCrl(caIdent, null));

    // keep only the latest CRL
    Assert.assertTrue(certstore.cleanupCrls(caIdent, 1) >= 1);
    Assert.assertNull(certstore.getEncodedCrl(caIdent, crl1.crlNumber().longValueExact()));
    Assert.assertArrayEquals(crl2.getEncoded(), certstore.getEncodedCrl(caIdent, crlNo2));
  }

  @Test
  public void isHealthy() {
    Assert.assertTrue(certstore.isHealthy());
  }

  private static X509Cert issue(String commonName) throws Exception {
    KeyCertBytesPair keyCert = caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null);
    return X509Util.parseCert(keyCert.cert());
  }

  private static List<BigInteger> serials(List<SerialWithId> list) {
    List<BigInteger> serials = new ArrayList<>(list.size());
    for (SerialWithId entry : list) {
      serials.add(entry.serial());
    }
    return serials;
  }

}
