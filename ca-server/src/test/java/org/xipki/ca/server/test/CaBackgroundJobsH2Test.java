// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x509.CRLEntry;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.server.Ca;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.x509.id.ExtensionOIDs;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Crl;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.misc.NameId;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

/**
 * The background jobs of the CA on in-memory H2 databases: revocation of certificates
 * suspended for too long, removal of expired certificates, and delta CRLs. The jobs are
 * scheduled (hourly, daily, by the CRL control); the test runs them directly.
 *
 * @author Lijun Liao (xipki)
 */
public class CaBackgroundJobsH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    caManager = env.caManager();

    ChangeCaEntry change = new ChangeCaEntry(new NameId(null, CA));
    change.setRevokeSuspendedControl("enabled=true,targetReason=cessationOfOperation,"
        + "unchangedSince=1h");
    change.setKeepExpiredCertDays(10);
    change.setCrlControl("interval.hours=24,fullcrl.intervals=7,deltacrl.intervals=1,"
        + "overlap=90d,interval.time=02:00");
    caManager.changeCa(change);
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  // ---------------------------------------------------------------- suspended certificates

  @Test
  public void certificatesSuspendedForTooLongAreRevoked() throws Exception {
    BigInteger old = issue("suspended-old.example.org");
    BigInteger recent = issue("suspended-recent.example.org");
    caManager.revokeCertificate(CA, old, CrlReason.CERTIFICATE_HOLD, null);
    caManager.revokeCertificate(CA, recent, CrlReason.CERTIFICATE_HOLD, null);
    // last change 2 hours ago, longer than unchangedSince=1h
    setColumn(old, "LUPDATE", Instant.now().minus(2, ChronoUnit.HOURS).getEpochSecond());

    runJob("revokerModule", "SuspendedCertsRevoker");

    Assert.assertEquals(CrlReason.CESSATION_OF_OPERATION,
        caManager.getCert(CA, old).revInfo().reason());
    Assert.assertEquals(CrlReason.CERTIFICATE_HOLD,
        caManager.getCert(CA, recent).revInfo().reason());
  }

  // ---------------------------------------------------------------- expired certificates

  @Test
  public void expiredCertificatesAreRemoved() throws Exception {
    BigInteger longExpired = issue("expired-long.example.org");
    BigInteger shortExpired = issue("expired-short.example.org");
    BigInteger valid = issue("expired-not.example.org");
    // keepExpiredCertDays=10
    setColumn(longExpired, "NAFTER", Instant.now().minus(20, ChronoUnit.DAYS).getEpochSecond());
    setColumn(shortExpired, "NAFTER", Instant.now().minus(2, ChronoUnit.DAYS).getEpochSecond());

    runJob("removerModule", "ExpiredCertsRemover");

    Assert.assertNull("removed", caManager.getCert(CA, longExpired));
    Assert.assertNotNull("kept, expired only 2 days ago", caManager.getCert(CA, shortExpired));
    Assert.assertNotNull("kept, not expired", caManager.getCert(CA, valid));
  }

  // ---------------------------------------------------------------- delta CRL

  @Test
  public void deltaCrlContainsTheRevocationsSinceTheFullCrl() throws Exception {
    BigInteger before = issue("delta-before.example.org");
    caManager.revokeCertificate(CA, before, CrlReason.KEY_COMPROMISE, null);
    X509Crl fullCrl = caManager.generateCrlOnDemand(CA).x509Crl();
    Assert.assertTrue(revokedSerials(fullCrl).contains(before));

    BigInteger after = issue("delta-after.example.org");
    caManager.revokeCertificate(CA, after, CrlReason.KEY_COMPROMISE, null);
    X509Crl deltaCrl = generateDeltaCrl();

    CertificateList delta = CertificateList.fromEncoded(deltaCrl.getEncoded());
    Assert.assertNotNull("deltaCRLIndicator", delta.getTBSCertList().getExtensions()
        .getExtension(ExtensionOIDs.deltaCRLIndicator));
    Assert.assertTrue("delta CRL number after the full CRL",
        deltaCrl.crlNumber().compareTo(fullCrl.crlNumber()) > 0);

    Set<BigInteger> serials = revokedSerials(deltaCrl);
    Assert.assertTrue("revoked after the full CRL", serials.contains(after));
    Assert.assertFalse("already in the full CRL", serials.contains(before));
  }

  // ---------------------------------------------------------------- helpers

  private static BigInteger issue(String commonName) throws Exception {
    return X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null).cert()).serialNumber();
  }

  private static void setColumn(BigInteger serial, String column, long value) throws Exception {
    try (Connection conn = env.caDatasource().getConnection();
         PreparedStatement ps = conn.prepareStatement(
             "UPDATE CERT SET " + column + "=? WHERE SN=?")) {
      ps.setLong(1, value);
      ps.setString(2, serial.toString(16));
      Assert.assertEquals("updated rows", 1, ps.executeUpdate());
    }
  }

  /** Runs the private scheduled job (inner Runnable class) of a module of the CA. */
  private static void runJob(String moduleField, String jobClass) throws Exception {
    Object module = field(caManager.getCaInstance(CA), moduleField);
    Class<?> clazz = Class.forName(module.getClass().getName() + "$" + jobClass);
    Constructor<?> constructor = clazz.getDeclaredConstructor(module.getClass());
    constructor.setAccessible(true);
    ((Runnable) constructor.newInstance(module)).run();
  }

  private static X509Crl generateDeltaCrl() throws Exception {
    Ca ca = caManager.getCaInstance(CA);
    Object crlModule = field(ca, "crlModule");
    Method method = crlModule.getClass().getDeclaredMethod("generateCrl", boolean.class,
        RequestorInfo.class, boolean.class, Instant.class, Instant.class);
    method.setAccessible(true);
    RequestorInfo requestor = new RequestorInfo.ByCaRequestorInfo(
        caManager.idNameMap().getRequestor(RequestorInfo.NAME_BY_CA));
    Instant now = Instant.now();
    return (X509Crl) method.invoke(crlModule, false, requestor, true, now,
        now.plus(1, ChronoUnit.DAYS));
  }

  private static Object field(Object obj, String name) throws Exception {
    Field field = obj.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(obj);
  }

  private static Set<BigInteger> revokedSerials(X509Crl crl) throws Exception {
    Set<BigInteger> serials = new HashSet<>();
    CertificateList list = CertificateList.fromEncoded(crl.getEncoded());
    if (list.getRevokedCertificates() != null) {
      for (CRLEntry entry : list.getRevokedCertificates()) {
        serials.add(entry.getUserCertificate().getValue());
      }
    }
    return serials;
  }

}
