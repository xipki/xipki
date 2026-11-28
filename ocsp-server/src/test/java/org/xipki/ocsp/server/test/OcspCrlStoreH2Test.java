// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.OcspCertStatus;
import org.xipki.asn1.x509.CRLReason;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The OCSP server with the store type {@code crl}: the CRL of the CA, provided in the folder
 * {@code crl-<name>} with {@code ca.crt}, {@code ca.crl} and {@code UPDATEME}, is imported
 * into the OCSP database of the store.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspCrlStoreH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static OcspServer server;

  private static Responder responder;

  private static X509Cert caCert;

  private static BigInteger good;

  private static BigInteger revoked;

  private static BigInteger onHold;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    CaManagerImpl caManager = env.caManager();
    caCert = env.caCert();

    good = issue(caManager, "crl-good.example.org");
    revoked = issue(caManager, "crl-revoked.example.org");
    onHold = issue(caManager, "crl-hold.example.org");
    caManager.revokeCertificate(CA, revoked, CrlReason.KEY_COMPROMISE, null);
    caManager.revokeCertificate(CA, onHold, CrlReason.CERTIFICATE_HOLD, null);

    Path crlsDir = env.workDir().resolve("crls");
    Path crlDir = crlsDir.resolve("crl-" + CA);
    Files.createDirectories(crlDir);
    Files.write(crlDir.resolve("ca.crt"), caCert.getEncoded());
    Files.write(crlDir.resolve("ca.crl"), caManager.generateCrlOnDemand(CA).getEncoded());
    Files.createFile(crlDir.resolve("UPDATEME"));

    Path ocspDb = env.newDatabase("ocsp-crl", "ocsp-init.h2.sql");
    String dir = crlsDir.toAbsolutePath().toString().replace("\\", "/");
    server = new OcspServer(env.workDir().toString());
    server.setSecurityFactory(env.securities().securityFactory());
    server.setConfFile(OcspTestUtil.writeResponderConf(env.workDir(), ocspDb,
        "{\"datasource\": \"ocspdb\", \"type\": \"crl\", \"conf\": {\"dir\": \"" + dir
            + "\", \"startupDelay\": 0}}",
        "good", "").toString());
    server.init(true);
    responder = server.getResponder("responder1");
    Assert.assertNotNull("responder1", responder);

    // the CRL is imported in the background after the startup delay
    Path updateMe = crlDir.resolve("UPDATEME");
    long deadline = System.currentTimeMillis() + 30_000;
    while (Files.exists(updateMe) && System.currentTimeMillis() < deadline) {
      Thread.sleep(100);
    }
    Assert.assertFalse("CRL imported (UPDATEME removed)", Files.exists(updateMe));
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
  public void revokedCertificate() throws Exception {
    OcspCertStatus status = status(revoked);
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.keyCompromise, status.getRevoked().getRevocationReason());
  }

  @Test
  public void certificateOnHold() throws Exception {
    Assert.assertEquals(CRLReason.certificateHold,
        status(onHold).getRevoked().getRevocationReason());
  }

  @Test
  public void certificateNotInCrlIsGood() throws Exception {
    // a CRL lists only revoked certificates: unknownCertBehaviour good, as shipped
    Assert.assertEquals(OcspCertStatus.GOOD, status(good));
  }

  private static OcspCertStatus status(BigInteger serial) throws Exception {
    return OcspTestUtil.status(server, responder, caCert, serial);
  }

  private static BigInteger issue(CaManagerImpl caManager, String commonName) throws Exception {
    return X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null).cert()).serialNumber();
  }

}
