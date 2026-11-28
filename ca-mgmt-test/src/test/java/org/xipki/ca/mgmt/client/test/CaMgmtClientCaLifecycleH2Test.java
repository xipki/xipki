// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.client.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.servlet.CaMgmtTestServer;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.misc.NameId;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

/**
 * CA management via the client ({@link CaMgmtClient}), the parts not in
 * {@link CaMgmtClientH2Test}: publishers, generation and removal of a root CA, cross
 * certificates and the supported types.
 *
 * @author Lijun Liao (xipki)
 */
public class CaMgmtClientCaLifecycleH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static final String CROSS_PROFILE = Paths.get("..", "assemblies", "xipki-qa", "src",
      "assembly", "unfiltered", "xipki-qa-cli", "qa", "certprofile", "certprofile-cross.json")
      .toString();

  private static CaH2TestEnv env;

  private static CaManagerImpl server;

  private static CaMgmtTestServer httpServer;

  private static CaMgmtClient client;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(true);
    server = env.caManager();
    X509Cert mgmtCert = newKeypairWithCert().certChain()[0];
    httpServer = new CaMgmtTestServer(server, mgmtCert, mgmtCert);
    client = new CaMgmtClient();
    client.init(null, httpServer.url());
  }

  @AfterClass
  public static void shutdown() {
    if (httpServer != null) {
      httpServer.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void supportedTypes() throws Exception {
    Assert.assertTrue(client.getSupportedSignerTypes().contains("pkcs12"));
    Assert.assertTrue(client.getSupportedCertprofileTypes().contains("xijson"));
    Assert.assertTrue(client.getSupportedPublisherTypes().contains("ocsp"));
    Assert.assertTrue(client.getInactiveCaNames().isEmpty());
  }

  @Test
  public void publisherLifecycle() throws Exception {
    // certificates before the publisher exists
    for (int i = 0; i < 3; i++) {
      server.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
          "CN=pub" + i + ".example.org,O=myorg,C=DE", null, null);
    }

    String name = "publisher1";
    client.addPublisher(new PublisherEntry(new NameId(null, name), "ocsp",
        "datasource=ocsp,publish.goodcerts=false"));
    Assert.assertTrue(client.getPublisherNames().contains(name));
    PublisherEntry entry = client.getPublisher(name);
    Assert.assertEquals("ocsp", entry.type());
    Assert.assertEquals("datasource=ocsp,publish.goodcerts=false", entry.conf());

    client.changePublisher(name, null, "datasource=ocsp,publish.goodcerts=true");
    Assert.assertEquals("datasource=ocsp,publish.goodcerts=true",
        client.getPublisher(name).conf());
    assertError(() -> client.addPublisher(new PublisherEntry(new NameId(null, name), "ocsp",
        "datasource=ocsp")));

    client.addPublisherToCa(name, CA);
    Assert.assertTrue(client.getPublisherNamesForCa(CA).contains(name));

    // the certificates issued before are published by republish
    client.republishCertificates(CA, List.of(name), 1);
    Assert.assertEquals(caCertCount(), ocspCertCount());

    client.removePublisherFromCa(name, CA);
    Assert.assertFalse(client.getPublisherNamesForCa(CA).contains(name));
    client.removePublisher(name);
    Assert.assertFalse(client.getPublisherNames().contains(name));
    assertError(() -> client.getPublisher(name));
  }

  @Test
  public void rootCaLifecycle() throws Exception {
    String name = "rootca2";
    X509Cert cert = client.generateRootCa(CaH2TestEnv.newCaEntry(name), "rootca",
        "CN=" + name + ",O=myorg,C=DE", "2", null, null).x509Cert();
    // the profile orders the RDNs
    Assert.assertEquals("C=DE,O=myorg,CN=" + name, cert.subjectText().replace(", ", ","));
    Assert.assertTrue("self-signed", cert.isSelfSigned());
    Assert.assertTrue(client.getCaNames().contains(name));
    Assert.assertTrue(client.getSuccessfulCaNames().contains(name));
    Assert.assertEquals(CertVariant.ofX509(cert), client.getCaCerts(name).get(0));

    // the new CA issues certificates
    client.addCertprofileToCa(CaH2TestEnv.PROFILE_TLS, name);
    X509Cert issued = X509Util.parseCert(client.generateKeyCert(name, CaH2TestEnv.PROFILE_TLS,
        "CN=rootca2-ee.example.org,O=myorg,C=DE", null, null).cert());
    Assert.assertEquals(cert.subject(), issued.issuer());

    client.notifyCaChange();
    client.unlockCa();
    Assert.assertTrue(client.getSuccessfulCaNames().contains(name));

    // a second CA with the same name is rejected
    assertError(() -> client.generateRootCa(CaH2TestEnv.newCaEntry(name), "rootca",
        "CN=" + name + "-2,O=myorg,C=DE", "3", null, null));

    // a CA with certificates cannot be removed, nothing is changed
    CaMgmtException ex = Assert.assertThrows(CaMgmtException.class, () -> client.removeCa(name));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("cannot be removed"));
    Assert.assertTrue(client.getCaNames().contains(name));
    Assert.assertNotNull(client.getCa(name));
  }

  @Test
  public void caWithCrlCannotBeRemoved() throws Exception {
    String name = "rootca4";
    client.generateRootCa(CaH2TestEnv.newCaEntry(name), "rootca",
        "CN=" + name + ",O=myorg,C=DE", "4", null, null);
    client.generateCrlOnDemand(name);

    CaMgmtException ex = Assert.assertThrows(CaMgmtException.class, () -> client.removeCa(name));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("CRLs"));
    Assert.assertTrue(client.getCaNames().contains(name));
  }

  @Test
  public void caWithoutIssuedCertificatesCanBeRemoved() throws Exception {
    String name = "rootca3";
    client.generateRootCa(CaH2TestEnv.newCaEntry(name), "rootca",
        "CN=" + name + ",O=myorg,C=DE", "3", null, null);
    Assert.assertTrue(client.getCaNames().contains(name));

    client.removeCa(name);
    Assert.assertFalse(client.getCaNames().contains(name));
    assertError(() -> client.getCa(name));
  }

  @Test
  public void crossCertificate() throws Exception {
    String profile = "cross";
    client.addCertprofile(new CertprofileEntry(new NameId(null, profile), "xijson",
        Files.readString(Paths.get(CROSS_PROFILE), StandardCharsets.UTF_8)));
    client.addCertprofileToCa(profile, CA);

    // the target: the certificate of another root CA, whose key is known
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    X509KeypairWithCert target;
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      target = X509KeypairWithCert.fromPKCS12Keystore(in, password, null, password,
          (X509Cert) null);
    }
    CaEntry targetCa = CaH2TestEnv.newCaEntry("crosstarget");
    targetCa.setSignerConf("algo=" + CaH2TestEnv.SIG_ALGO + ",password=CHANGEIT,keystore=base64:"
        + Base64.encodeToString(keystore));
    X509Cert targetCert = server.generateRootCa(targetCa, "rootca",
        "CN=crosstarget,O=otherorg,C=DE", "1", null, null).x509Cert();

    byte[] csr = new CertificationRequest.CsrBuilder(targetCert.subject(),
        targetCert.subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(target.getKey(), target.publicKey()).contentSigner())
        .getEncoded();

    X509Cert cross = client.generateCrossCertificate(CA, profile, csr,
        targetCert.getEncoded(), null, null).x509Cert();
    Assert.assertEquals(env.caCert().subject(), cross.issuer());
    Assert.assertEquals(targetCert.subject(), cross.subject());
    Assert.assertEquals(targetCert.publicKey(), cross.publicKey());
    Assert.assertFalse(cross.notAfter().isAfter(targetCert.notAfter()));

    // a profile not for cross certificates is rejected
    assertError(() -> client.generateCrossCertificate(CA, CaH2TestEnv.PROFILE_TLS, csr,
        targetCert.getEncoded(), null, null));

    // the CSR must belong to the target certificate
    assertError(() -> client.generateCrossCertificate(CA, profile, csr,
        env.caCert().getEncoded(), null, null));
  }

  // ---------------------------------------------------------------- helpers

  private interface Call {
    void call() throws Exception;
  }

  private static void assertError(Call call) {
    Assert.assertThrows(CaMgmtException.class, call::call);
  }

  private static X509KeypairWithCert newKeypairWithCert() throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, password, null, password,
          (X509Cert) null);
    }
  }

  /** Number of certificates of {@link #CA} in the CA database. */
  private static int caCertCount() throws Exception {
    int caId = server.idNameMap().getCa(CA).id();
    try (Connection conn = env.caDatasource().getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM CERT WHERE CA_ID=" + caId)) {
      rs.next();
      return rs.getInt(1);
    }
  }

  private static int ocspCertCount() throws Exception {
    Path conf = env.ocspDbConf();
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    try (DataSourceWrapper datasource = new DataSourceFactory().createDataSource("ocsp-test",
        props)) {
      return datasource.getCount(null, "CERT");
    }
  }

}
