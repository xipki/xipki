// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.OcspCertStatus;
import org.xipki.asn1.x509.CRLReason;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.misc.NameId;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;

/**
 * The OCSP publisher of the CA ({@code OcspCertPublisher}) and the OCSP server with the store
 * type {@code xipki-db}: the CA publishes its certificates and their revocation into the
 * OCSP database, the OCSP server answers from it.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspPublisherH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static final String PUBLISHER = "ocsp-publisher";

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  private static OcspServer server;

  private static Responder responder;

  private static X509Cert caCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(true);
    caManager = env.caManager();
    caCert = env.caCert();

    // the publisher publishes the CA when it is added to the CA
    caManager.addPublisher(new PublisherEntry(new NameId(null, PUBLISHER), "ocsp",
        "datasource=ocsp,publish.goodcerts=true"));
    caManager.addPublisherToCa(PUBLISHER, CA);

    server = new OcspServer(env.workDir().toString());
    server.setSecurityFactory(env.securities().securityFactory());
    server.setConfFile(OcspTestUtil.writeResponderConf(env.workDir(), env.ocspDbConf(),
        "{\"datasource\": \"ocspdb\", \"type\": \"xipki-db\", \"conf\": {}}", "unknown", "")
        .toString());
    server.init(true);
    responder = server.getResponder("responder1");
    Assert.assertNotNull("responder1", responder);
  }

  @AfterClass
  public static void shutdown() {
    if (server != null) {
      server.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void goodCertificate() throws Exception {
    BigInteger serial = issue("ocsp-good.example.org");
    Assert.assertEquals("good", OcspCertStatus.GOOD, status(serial));
  }

  @Test
  public void revokedCertificate() throws Exception {
    BigInteger serial = issue("ocsp-revoked.example.org");
    caManager.revokeCertificate(CA, serial, CrlReason.KEY_COMPROMISE, null);
    OcspCertStatus status = status(serial);
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.keyCompromise, status.getRevoked().getRevocationReason());
  }

  @Test
  public void suspendedAndUnsuspendedCertificate() throws Exception {
    BigInteger serial = issue("ocsp-hold.example.org");
    caManager.revokeCertificate(CA, serial, CrlReason.CERTIFICATE_HOLD, null);
    Assert.assertEquals(CRLReason.certificateHold,
        status(serial).getRevoked().getRevocationReason());

    caManager.unsuspendCertificate(CA, serial);
    Assert.assertEquals("good after unsuspend", OcspCertStatus.GOOD, status(serial));
  }

  /** RFC 6960, section 2.2: non-issued certificates are revoked, certificateHold, time 0. */
  @Test
  public void removedCertificateIsNonIssued() throws Exception {
    BigInteger serial = issue("ocsp-removed.example.org");
    caManager.removeCertificate(CA, serial);
    assertNonIssued(status(serial));
  }

  @Test
  public void neverIssuedCertificateIsNonIssued() throws Exception {
    assertNonIssued(status(new BigInteger("123456789")));
  }

  @Test
  public void republishAfterClearingTheOcspDatabase() throws Exception {
    BigInteger serial = issue("ocsp-republish.example.org");
    try (DataSourceWrapper ocspDb = datasource(env.ocspDbConf());
         Connection conn = ocspDb.getConnection();
         Statement stmt = conn.createStatement()) {
      stmt.executeUpdate("DELETE FROM CERT");
    }
    assertNonIssued(status(serial));

    caManager.republishCertificates(CA, List.of(PUBLISHER), 1);
    Assert.assertEquals("good", OcspCertStatus.GOOD, status(serial));
  }

  // ---------------------------------------------------------------- helpers

  private static void assertNonIssued(OcspCertStatus status) {
    OcspTestUtil.assertNonIssued(status);
  }

  private static DataSourceWrapper datasource(Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return new DataSourceFactory().createDataSource("ocsp-test", props);
  }

  private static BigInteger issue(String commonName) throws Exception {
    return X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null).cert()).serialNumber();
  }

  private static OcspCertStatus status(BigInteger serial) throws Exception {
    return OcspTestUtil.status(server, responder, caCert, serial);
  }

}
