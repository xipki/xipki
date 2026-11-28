// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.client.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.SimpleProfileInfo;
import org.xipki.pkix.ca.CertLevel;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.servlet.CaMgmtTestServer;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.CertRevocationInfo;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.KeyCertBytesPair;
import org.xipki.pkix.cert.NameVariant;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.cert.X509Crl;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.conf.Validity;
import org.xipki.util.misc.NameId;
import org.xipki.util.misc.PemEncoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * The CA management client {@link CaMgmtClient} against the management servlet of a CA on
 * in-memory H2 databases. The results seen by the client are compared with the CA manager
 * on the server side.
 *
 * @author Lijun Liao (xipki)
 */
public class CaMgmtClientH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static CaManagerImpl server;

  private static CaMgmtTestServer httpServer;

  private static X509Cert mgmtCert;

  private static CaMgmtClient client;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    server = env.caManager();
    mgmtCert = newCert();
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

  // ---------------------------------------------------------------- system and CA

  @Test
  public void systemStatusAndCaNames() throws Exception {
    Assert.assertEquals(CaSystemStatus.STARTED_AS_MASTER, client.getCaSystemStatus());
    Assert.assertEquals(server.getCaNames(), client.getCaNames());
    Assert.assertTrue(client.getSuccessfulCaNames().contains(CA));
    Assert.assertTrue(client.getFailedCaNames().isEmpty());
    Assert.assertTrue(client.getSupportedCertprofileTypes().contains("xijson"));
  }

  @Test
  public void getCa() throws Exception {
    CaEntry expected = server.getCa(CA);
    CaEntry ca = client.getCa(CA);
    Assert.assertEquals(expected.ident(), ca.ident());
    Assert.assertEquals(expected.cert(), ca.cert());
    Assert.assertEquals(expected.base().status(), ca.base().status());
    Assert.assertEquals(expected.base().caUris(), ca.base().caUris());
    Assert.assertEquals(List.of(CertVariant.ofX509(env.caCert())), client.getCaCerts(CA));
  }

  @Test
  public void unknownCa() {
    CaMgmtException ex = Assert.assertThrows(CaMgmtException.class,
        () -> client.getCa("no-such-ca"));
    Assert.assertNotNull(ex.getMessage());
  }

  @Test
  public void caAlias() throws Exception {
    client.addCaAlias("alias1", CA);
    Assert.assertEquals(CA, client.getCaNameForAlias("alias1"));
    Assert.assertTrue(client.getAliasesForCa(CA).contains("alias1"));
    Assert.assertTrue(client.getCaAliasNames().contains("alias1"));
    Assert.assertEquals(CA, server.getCaNameForAlias("alias1"));

    client.removeCaAlias("alias1");
    Assert.assertNull(server.getCaNameForAlias("alias1"));
  }

  @Test
  public void dbSchema() throws Exception {
    client.addDbSchema("TEST_KEY", "v1");
    Assert.assertEquals("v1", client.getDbSchemas().get("TEST_KEY"));
    client.changeDbSchema("TEST_KEY", "v2");
    Assert.assertEquals("v2", server.getDbSchemas().get("TEST_KEY"));
    client.removeDbSchema("TEST_KEY");
    Map<String, String> schemas = client.getDbSchemas();
    Assert.assertFalse(schemas.containsKey("TEST_KEY"));
  }

  @Test
  public void changeCa() throws Exception {
    int numCrls = server.getCa(CA).base().numCrls();
    ChangeCaEntry change = new ChangeCaEntry(new NameId(null, CA));
    change.setNumCrls(numCrls + 5);
    change.setMaxValidity(Validity.getInstance("5y"));
    client.changeCa(change);
    try {
      Assert.assertEquals(numCrls + 5, server.getCa(CA).base().numCrls());
      Assert.assertEquals(Validity.getInstance("5y"), server.getCa(CA).base().maxValidity());
      Assert.assertEquals(numCrls + 5, client.getCa(CA).base().numCrls());
    } finally {
      ChangeCaEntry restore = new ChangeCaEntry(new NameId(null, CA));
      restore.setNumCrls(numCrls);
      restore.setMaxValidity(Validity.getInstance("10y"));
      client.changeCa(restore);
    }
  }

  @Test
  public void revokeAndUnrevokeCa() throws Exception {
    client.revokeCa(CA, new CertRevocationInfo(CrlReason.CERTIFICATE_HOLD));
    try {
      Assert.assertEquals(CrlReason.CERTIFICATE_HOLD,
          server.getCa(CA).base().revocationInfo().reason());
    } finally {
      client.unrevokeCa(CA);
    }
    Assert.assertNull(client.getCa(CA).base().revocationInfo());
  }

  @Test
  public void revokedCaCanBeRead() throws Exception {
    client.revokeCa(CA, new CertRevocationInfo(CrlReason.CERTIFICATE_HOLD));
    try {
      Assert.assertEquals(CrlReason.CERTIFICATE_HOLD,
          client.getCa(CA).base().revocationInfo().reason());
    } finally {
      client.unrevokeCa(CA);
    }
  }

  @Test
  public void restartCa() throws Exception {
    client.restartCa(CA);
    Assert.assertTrue(client.getSuccessfulCaNames().contains(CA));
  }

  @Test
  public void simpleCertprofileInfo() throws Exception {
    SimpleProfileInfo info = client.getSimpleCertprofileInfo(CaH2TestEnv.PROFILE_TLS);
    Assert.assertEquals(CertLevel.EndEntity, info.getCertLevel());
    Assert.assertEquals("5y", info.getValidity());
  }

  @Test
  public void keypairGenLifecycle() throws Exception {
    // the name software is reserved
    Assert.assertThrows(CaMgmtException.class,
        () -> client.addKeypairGen(new KeypairGenEntry("software", "software", null)));

    client.addKeypairGen(new KeypairGenEntry("kg1", "software", null));
    Assert.assertTrue(client.getKeypairGenNames().contains("kg1"));
    Assert.assertEquals("software", client.getKeypairGen("kg1").type());
    client.removeKeypairGen("kg1");
    Assert.assertFalse(server.getKeypairGenNames().contains("kg1"));
  }

  @Test
  public void signerLifecycle() throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    String conf = "password=CHANGEIT,algo=SHA256withECDSA,keystore=base64:"
        + Base64.encodeToString(keystore);
    client.addSigner(new SignerEntry("signer1", "pkcs12", conf, null));
    Assert.assertTrue(client.getSignerNames().contains("signer1"));
    SignerEntry signer = client.getSigner("signer1");
    Assert.assertEquals("pkcs12", signer.type());
    Assert.assertNotNull(server.getSigner("signer1"));

    client.removeSigner("signer1");
    Assert.assertFalse(server.getSignerNames().contains("signer1"));
  }

  // ---------------------------------------------------------------- certificate profiles

  @Test
  public void certprofileLifecycle() throws Exception {
    String conf = resource("/certprofile/certprofile-tls-ec.json");
    client.addCertprofile(new CertprofileEntry(new NameId(null, "mgmt-tls"), "xijson", conf));
    Assert.assertTrue(client.getCertprofileNames().contains("mgmt-tls"));
    CertprofileEntry entry = client.getCertprofile("mgmt-tls");
    Assert.assertEquals("xijson", entry.type());
    Assert.assertNotNull(server.getCertprofile("mgmt-tls"));

    // change the configuration: the validity
    String changed = conf.replace("\"validity\": \"5y\"", "\"validity\": \"2y\"");
    Assert.assertNotEquals(conf, changed);
    client.changeCertprofile("mgmt-tls", null, changed);
    Assert.assertTrue(server.getCertprofile("mgmt-tls").conf().contains("\"2y\""));

    // assign to the CA with an alias
    client.addCertprofileToCa("mgmt-tls:mgmt-tls-alias", CA);
    boolean found = false;
    for (CaProfileEntry e : client.getCertprofilesForCa(CA)) {
      if (e.profileName().equals("mgmt-tls")) {
        found = true;
        Assert.assertEquals(List.of("mgmt-tls-alias"), e.profileAliases());
      }
    }
    Assert.assertTrue("profile assigned to the CA", found);

    client.removeCertprofileFromCa("mgmt-tls", CA);
    client.removeCertprofile("mgmt-tls");
    Assert.assertFalse(client.getCertprofileNames().contains("mgmt-tls"));
    Assert.assertNull(server.getCertprofile("mgmt-tls"));
  }

  @Test
  public void invalidCertprofileIsRejected() {
    Assert.assertThrows(CaMgmtException.class, () -> client.addCertprofile(
        new CertprofileEntry(new NameId(null, "invalid"), "xijson", "{\"no\": \"profile\"}")));
    Assert.assertNull(server.getCertprofile("invalid"));
  }

  // ---------------------------------------------------------------- requestors

  @Test
  public void requestorLifecycle() throws Exception {
    String pem = new String(PemEncoder.encode(newCert().getEncoded(),
        PemEncoder.PemLabel.CERTIFICATE), StandardCharsets.US_ASCII);
    client.addRequestor(new RequestorEntry(new NameId(null, "ra1"), RequestorEntry.TYPE_CERT,
        pem));
    Assert.assertTrue(client.getRequestorNames().contains("ra1"));
    Assert.assertEquals(RequestorEntry.TYPE_CERT, client.getRequestor("ra1").type());

    client.addRequestorToCa(new CaHasRequestorEntry(new NameId(null, "ra1"),
        new Permissions(PermissionConstants.ENROLL_CERT | PermissionConstants.REVOKE_CERT),
        List.of(CaH2TestEnv.PROFILE_TLS)), CA);
    CaHasRequestorEntry assigned = null;
    for (CaHasRequestorEntry e : client.getRequestorsForCa(CA)) {
      if (e.requestorIdent().name().equals("ra1")) {
        assigned = e;
      }
    }
    Assert.assertNotNull(assigned);
    Assert.assertTrue(assigned.isPermitted(PermissionConstants.ENROLL_CERT));
    Assert.assertFalse(assigned.isPermitted(PermissionConstants.GEN_CRL));
    Assert.assertTrue(assigned.isCertprofilePermitted(CaH2TestEnv.PROFILE_TLS));

    client.removeRequestorFromCa("ra1", CA);
    client.removeRequestor("ra1");
    Assert.assertFalse(server.getRequestorNames().contains("ra1"));
  }

  // ---------------------------------------------------------------- certificates and CRLs

  @Test
  public void certificateLifecycle() throws Exception {
    X509Cert cert = client.generateCertificate(CA, CaH2TestEnv.PROFILE_TLS,
        csr("mgmt.example.org"), null, null).x509Cert();
    cert.verify(env.caCert().publicKey());
    BigInteger serial = cert.serialNumber();

    CertWithRevocationInfo info = client.getCert(CA, serial);
    Assert.assertEquals(cert, info.cert().x509Cert());
    Assert.assertFalse(info.isRevoked());
    // by issuer and serial number
    Assert.assertEquals(cert,
        client.getCert(NameVariant.ofX509(env.caCert().subject()), serial).cert().x509Cert());

    client.revokeCertificate(CA, serial, CrlReason.CERTIFICATE_HOLD, null);
    Assert.assertTrue(server.getCert(CA, serial).isRevoked());
    client.unsuspendCertificate(CA, serial);
    Assert.assertFalse(server.getCert(CA, serial).isRevoked());

    client.removeCertificate(CA, serial);
    Assert.assertNull(server.getCert(CA, serial));
  }

  @Test
  public void getCertShowsRevocationAndProfile() throws Exception {
    X509Cert cert = client.generateCertificate(CA, CaH2TestEnv.PROFILE_TLS,
        csr("revoked.example.org"), null, null).x509Cert();
    BigInteger serial = cert.serialNumber();
    Assert.assertEquals(CaH2TestEnv.PROFILE_TLS, client.getCert(CA, serial).certprofile());

    client.revokeCertificate(CA, serial, CrlReason.KEY_COMPROMISE, null);
    CertWithRevocationInfo info = client.getCert(CA, serial);
    Assert.assertTrue(info.isRevoked());
    Assert.assertEquals(CrlReason.KEY_COMPROMISE, info.revInfo().reason());
  }

  @Test
  public void keyAndCertificateGeneration() throws Exception {
    KeyCertBytesPair keyCert = client.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=keycert.example.org,O=myorg,C=DE", null, null);
    Assert.assertNotNull(keyCert.key());
    X509Cert cert = X509Util.parseCert(keyCert.cert());
    Assert.assertNotNull(server.getCert(CA, cert.serialNumber()));
  }

  @Test
  public void listCertificates() throws Exception {
    X509Cert cert = client.generateCertificate(CA, CaH2TestEnv.PROFILE_TLS,
        csr("list.example.org"), null, null).x509Cert();
    List<CertListInfo> list = client.listCertificates(CA, null, null, null,
        CertListOrderBy.NOT_BEFORE_DESC, 1000);
    List<BigInteger> serials = new ArrayList<>();
    for (CertListInfo i : list) {
      serials.add(i.serialNumber());
    }
    Assert.assertTrue(serials.contains(cert.serialNumber()));
  }

  @Test
  public void crls() throws Exception {
    X509Crl crl = client.generateCrlOnDemand(CA).x509Crl();
    Assert.assertEquals(env.caCert().subject(), crl.issuer());
    Assert.assertArrayEquals(crl.getEncoded(), client.getCurrentCrl(CA).getEncoded());
    Assert.assertArrayEquals(crl.getEncoded(),
        client.getCrl(CA, crl.crlNumber().longValueExact()).getEncoded());
  }

  // ---------------------------------------------------------------- configuration

  @Test
  public void exportConf() throws Exception {
    List<String> names = new ArrayList<>();
    try (ZipInputStream zip = new ZipInputStream(client.exportConf(List.of(CA)))) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        names.add(entry.getName());
      }
    }
    Assert.assertTrue(names.toString(), names.contains("caconf.json"));
  }

  // ---------------------------------------------------------------- authorization

  @Test
  public void otherClientCertificateIsRejected() throws Exception {
    httpServer.setClientCert(newCert());
    try {
      CaMgmtException ex = Assert.assertThrows(CaMgmtException.class,
          () -> client.getCaNames());
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("not permitted"));
    } finally {
      httpServer.setClientCert(mgmtCert);
    }
  }

  @Test
  public void missingClientCertificateIsRejected() throws Exception {
    httpServer.setClientCert(null);
    try {
      CaMgmtException ex = Assert.assertThrows(CaMgmtException.class,
          () -> client.getCaNames());
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("not permitted"));
    } finally {
      httpServer.setClientCert(mgmtCert);
    }
  }

  // ---------------------------------------------------------------- helpers

  private static X509Cert newCert() throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, password, null, password,
          (X509Cert) null).certChain()[0];
    }
  }

  private static byte[] csr(String commonName) throws Exception {
    X509KeyPairWithSubjectPublicKeyInfo kp = KeyUtil.generateX509KeyPair2(KeySpec.P256);
    return new CertificationRequest.CsrBuilder(
        new X500Name("CN=" + commonName + ",O=myorg,C=DE"), kp.subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(kp.keypair().getPrivate(), kp.keypair().getPublic())
            .contentSigner())
        .getEncoded();
  }

  private static String resource(String name) throws IOException {
    try (InputStream in = CaMgmtClientH2Test.class.getResourceAsStream(name)) {
      if (in == null) {
        throw new IOException("resource " + name + " not found");
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

}
