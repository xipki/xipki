// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Attribute;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.gateway.scep.CaNameScepSigners;
import org.xipki.ca.gateway.scep.ScepControl;
import org.xipki.ca.gateway.scep.ScepHttpServlet;
import org.xipki.ca.gateway.scep.ScepProtocolConf;
import org.xipki.ca.gateway.scep.ScepResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.auth.SimpleRequestorAuthenticator;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.scep.client.ScepClientException;
import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.misc.NameId;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.time.Instant;
import java.util.List;

/**
 * The SCEP responder of the gateway ({@link ScepResponder}, {@link ScepHttpServlet}) with the
 * SCEP client of pki-client ({@link ScepClient}), against the CA of {@link GatewayTestEnv}.
 * The responder has an RSA key (SCEP encrypts the requests to it); clients authenticate with
 * the challenge password {@code <user>:<password>}.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepResponderTest {

  private static final String CA = GatewayTestEnv.CA;

  private static final String SETUP_PROFILES =
      "../assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/ca-setup/certprofile";

  /** The shipped profile tls, which permits RSA keys. */
  private static final String PROFILE = "scep-tls";

  private static GatewayTestEnv env;

  private static ServletTestServer server;

  private static ServletTestServer singleRaServer;

  private static X509Cert caCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    CaManagerImpl caManager = env.ca().caManager();
    // the shipped profiles: tls for the clients, scep* for the RA certificates
    addProfile(caManager, PROFILE, "tls");
    for (String name : new String[]{"scep", "scep-sign", "scep-enc"}) {
      addProfile(caManager, name, name);
    }
    caCert = env.ca().caCert();

    SecurityFactory securityFactory = env.ca().securities().securityFactory();
    // as shipped: separate RA certificates for signature and encryption
    RaKey sign = newRaKey(caManager, "scep-sign");
    RaKey enc = newRaKey(caManager, "scep-enc");
    ConcurrentSigner responderSigner = sign.signer(securityFactory);
    ScepProtocolConf.CaNameDecryptorsConf decryptors = new ScepProtocolConf.CaNameDecryptorsConf(
        enc.decryptorConf(), null);

    Path requestorsConf = env.ca().workDir().resolve("scep-requestors.json");
    Files.writeString(requestorsConf, "{\"passwords\": [{\"user\": \"" + GatewayTestEnv.USER
        + "\", \"password\": \"" + GatewayTestEnv.PASSWORD + "\",\n"
        + "  \"protocols\": [\"SCEP\"], \"permissions\": [\"ALL\"],\n"
        + "  \"caProfiles\": [{\"ca\": \"ALL\", \"profiles\": [\"ALL\"]}]}]}\n");
    SimpleRequestorAuthenticator authenticator = new SimpleRequestorAuthenticator();
    authenticator.init(requestorsConf.toString(), null);

    ScepControl control = new ScepControl();
    control.setIncludeCaCert(true);
    control.setIncludeSignerCert(true);
    control.setSupportGetCrl(true);

    GatewayConf.CaProfilesControl caProfiles = new GatewayConf.CaProfilesControl(List.of(
        new GatewayConf.CaProfileConf("scep", CA, PROFILE)));
    ScepResponder responder = new ScepResponder(control, env.sdk(), securityFactory,
        new CaNameScepSigners(new CaNameSigners(responderSigner, null), decryptors, null),
        authenticator, env.popControl(), caProfiles);
    server = new ServletTestServer("/scep", new ScepHttpServlet(false, responder)::service,
        null);

    // one RA certificate for signature and encryption (shipped profile scep), no decryptor
    ScepResponder singleRaResponder = new ScepResponder(control, env.sdk(), securityFactory,
        new CaNameScepSigners(new CaNameSigners(
            newRaKey(caManager, "scep").signer(securityFactory), null)),
        authenticator, env.popControl(), caProfiles);
    singleRaServer = new ServletTestServer("/scep",
        new ScepHttpServlet(false, singleRaResponder)::service, null);
  }

  @AfterClass
  public static void shutdown() {
    if (server != null) {
      server.close();
    }
    if (singleRaServer != null) {
      singleRaServer.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void caCapsAndCaCert() throws Exception {
    ScepClient client = newClient();
    client.init();
    Assert.assertEquals(caCert, client.caCert());
    Assert.assertNotNull(client.caCaps());
  }

  @Test
  public void enrollWithChallengePassword() throws Exception {
    Identity identity = newIdentity("scep1.example.org");
    EnrolmentResponse response = newClient().scepEnrol(
        csr("scep1.example.org", identity, GatewayTestEnv.USER + ":" + GatewayTestEnv.PASSWORD),
        identity.key, identity.cert);
    if (!response.isSuccess()) {
      Assert.fail("no success: pending " + response.isPending() + ", failInfo "
          + (response.isFailure() ? response.failInfoText() : null));
    }
    X509Cert cert = response.certificates().get(0);
    cert.verify(caCert.publicKey());
    Assert.assertNotNull(env.ca().caManager().getCert(CA, cert.serialNumber()));
  }

  @Test
  public void wrongPasswordIsRejected() throws Exception {
    Identity identity = newIdentity("scep-wrong.example.org");
    EnrolmentResponse response = newClient().scepEnrol(
        csr("scep-wrong.example.org", identity, GatewayTestEnv.USER + ":wrong"),
        identity.key, identity.cert);
    Assert.assertTrue(response.isFailure());
  }

  @Test
  public void unknownAliasIsRejected() throws Exception {
    ScepClient client = new ScepClient(new CaIdentifier(server.url() + "unknown/pkiclient.exe",
        null), new CaCertValidator.PreprovisionedCaCertValidator(caCert));
    Assert.assertThrows(Exception.class, client::init);
  }

  @Test
  public void singleRaCertificate() throws Exception {
    ScepClient client = new ScepClient(new CaIdentifier(singleRaServer.url()
        + "scep/pkiclient.exe", null), new CaCertValidator.PreprovisionedCaCertValidator(caCert));
    client.init();
    Identity identity = newIdentity("scep-single.example.org");
    EnrolmentResponse response = client.scepEnrol(
        csr("scep-single.example.org", identity,
            GatewayTestEnv.USER + ":" + GatewayTestEnv.PASSWORD), identity.key, identity.cert);
    Assert.assertTrue(response.isSuccess());
  }

  // ---------------------------------------------------------------- helpers

  /** Key and certificate of an RA, the certificate is issued by the CA. */
  private static final class RaKey {

    private byte[] keystore;

    private X509Cert cert;

    ConcurrentSigner signer(SecurityFactory securityFactory) throws Exception {
      return securityFactory.createSigner("pkcs12", new SignerConf(
          "password=CHANGEIT,algo=SHA256withRSA,keystore=base64:"
              + Base64.encodeToString(keystore)), CertVariant.ofX509(cert));
    }

    GatewayConf.SignerConf decryptorConf() {
      return new GatewayConf.SignerConf("pkcs12",
          "password=CHANGEIT,keystore=base64:" + Base64.encodeToString(keystore),
          List.of(FileOrBinary.ofBinary(cert.getEncoded())));
    }

  }

  private static void addProfile(CaManagerImpl caManager, String name, String file)
      throws Exception {
    caManager.addCertprofile(new CertprofileEntry(new NameId(null, name), "xijson",
        Files.readString(Paths.get(SETUP_PROFILES, "certprofile-" + file + ".json"))));
    caManager.addCertprofileToCa(name, CA);
  }

  /** Self-signed RSA identity of a SCEP client, its key is also the key of the CSR. */
  // ---------------------------------------------------------------- renewal, GetCert, GetCRL

  @Test
  public void renewalWithIssuedCertificateAndPassword() throws Exception {
    Identity issued = enrolled("scep-renew.example.org");
    // signed with the issued certificate, new key in the CSR
    Identity newKey = newIdentity("scep-renew.example.org");
    CertificationRequest csr = new CertificationRequest.CsrBuilder(
        new X500Name("CN=scep-renew.example.org,O=myorg,C=DE"),
        newKey.cert.subjectPublicKeyInfo())
        .setAttribute(Attribute.ofChallengePassword(
            GatewayTestEnv.USER + ":" + GatewayTestEnv.PASSWORD))
        .build(KeyUtil.getSigner(newKey.key, newKey.cert.publicKey()).contentSigner());
    EnrolmentResponse response = newClient().scepRenewalReq(csr, issued.key, issued.cert);
    assertSuccess(response);
    X509Cert renewed = response.certificates().get(0);
    Assert.assertEquals(newKey.cert.publicKey(), renewed.publicKey());
    Assert.assertNotEquals(issued.cert.serialNumber(), renewed.serialNumber());
  }

  /**
   * Renewal signed with a certificate issued by the CA, without challenge password: the
   * signature certificate must be a configured requestor certificate, an issued certificate is
   * not sufficient (current behavior).
   */
  @Test
  public void renewalWithoutPasswordNeedsRequestorCertificate() throws Exception {
    Identity issued = enrolled("scep-renew-nopwd.example.org");
    CertificationRequest csr = new CertificationRequest.CsrBuilder(
        new X500Name("CN=scep-renew-nopwd.example.org,O=myorg,C=DE"),
        issued.cert.subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(issued.key, issued.cert.publicKey()).contentSigner());
    EnrolmentResponse response = newClient().scepRenewalReq(csr, issued.key, issued.cert);
    Assert.assertTrue("rejected", response.isFailure());
  }

  @Test
  public void renewalWithSelfSignedCertificateIsRejected() throws Exception {
    Identity identity = newIdentity("scep-renew-selfsigned.example.org");
    CertificationRequest csr = csr("scep-renew-selfsigned.example.org", identity,
        GatewayTestEnv.USER + ":" + GatewayTestEnv.PASSWORD);
    // RFC 8894 3.3.1.2: rejected by the client already (the server check is not reachable)
    Assert.assertThrows(IllegalArgumentException.class,
        () -> newClient().scepRenewalReq(csr, identity.key, identity.cert));
  }

  @Test
  public void getCert() throws Exception {
    Identity issued = enrolled("scep-getcert.example.org");
    Identity requestor = newIdentity("scep-getcert-requestor.example.org");
    List<X509Cert> certs = newClient().scepGetCert(requestor.key, requestor.cert,
        caCert.subject(), issued.cert.serialNumber());
    Assert.assertEquals(issued.cert, certs.get(0));

    Assert.assertThrows(ScepClientException.class, () -> newClient().scepGetCert(requestor.key,
        requestor.cert, caCert.subject(), BigInteger.valueOf(0x7fffffffL)));
  }

  @Test
  public void getCrl() throws Exception {
    Identity issued = enrolled("scep-getcrl.example.org");
    env.ca().caManager().revokeCertificate(CA, issued.cert.serialNumber(),
        CrlReason.KEY_COMPROMISE, null);
    env.ca().caManager().generateCrlOnDemand(CA);

    Identity requestor = newIdentity("scep-getcrl-requestor.example.org");
    CertificateList crl = newClient().scepGetCrl(requestor.key, requestor.cert,
        caCert.subject(), issued.cert.serialNumber());
    Assert.assertNotNull(crl);
    X509CRL jceCrl = (X509CRL) CertificateFactory.getInstance("X.509")
        .generateCRL(new ByteArrayInputStream(crl.getEncoded()));
    jceCrl.verify(caCert.publicKey());
    Assert.assertNotNull("revoked certificate in the CRL",
        jceCrl.getRevokedCertificate(issued.cert.serialNumber()));
  }

  /** Enrolls a certificate: the identity with the issued certificate and its key. */
  private static Identity enrolled(String commonName) throws Exception {
    Identity identity = newIdentity(commonName);
    EnrolmentResponse response = newClient().scepEnrol(
        csr(commonName, identity, GatewayTestEnv.USER + ":" + GatewayTestEnv.PASSWORD),
        identity.key, identity.cert);
    assertSuccess(response);
    Identity issued = new Identity();
    issued.key = identity.key;
    issued.cert = response.certificates().get(0);
    return issued;
  }

  private static void assertSuccess(EnrolmentResponse response) throws Exception {
    if (!response.isSuccess()) {
      Assert.fail("no success: pending " + response.isPending() + ", failInfo "
          + (response.isFailure() ? response.failInfoText() : null));
    }
  }

  private static final class Identity {

    private PrivateKey key;

    private X509Cert cert;

  }

  private static ScepClient newClient() throws Exception {
    return new ScepClient(new CaIdentifier(server.url() + "scep/pkiclient.exe", null),
        new CaCertValidator.PreprovisionedCaCertValidator(caCert));
  }

  /** Self-signed identity: RFC 8894 requires the subject of the CSR. */
  private static Identity newIdentity(String commonName) throws Exception {
    X509KeyPairWithSubjectPublicKeyInfo kp = KeyUtil.generateX509KeyPair2(KeySpec.RSA2048);
    X500Name subject = new X500Name("CN=" + commonName + ",O=myorg,C=DE");
    Instant now = Instant.now();
    Certificate.V3CertBuilder builder = new Certificate.V3CertBuilder(subject, BigInteger.ONE,
        now.minusSeconds(60), now.plusSeconds(3600), subject, kp.subjectPublicKeyInfo());
    Identity identity = new Identity();
    identity.key = kp.keypair().getPrivate();
    identity.cert = new X509Cert(builder.build(
        KeyUtil.getSigner(kp.keypair().getPrivate(), kp.keypair().getPublic()).contentSigner()));
    return identity;
  }

  private static CertificationRequest csr(String commonName, Identity identity,
                                          String challengePassword) throws Exception {
    return new CertificationRequest.CsrBuilder(
        new X500Name("CN=" + commonName + ",O=myorg,C=DE"),
        identity.cert.subjectPublicKeyInfo())
        .setAttribute(Attribute.ofChallengePassword(challengePassword))
        .build(KeyUtil.getSigner(identity.key, identity.cert.publicKey()).contentSigner());
  }

  /** RSA key of an RA with a certificate issued by the CA with the given profile. */
  private static RaKey newRaKey(CaManagerImpl caManager, String profile) throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    RaKey ret = new RaKey();
    ret.keystore = KeyUtil.generateX509KeyPair3(KeySpec.RSA2048,
        new KeystoreGenerationParameters(password)).keystore();
    X509KeypairWithCert kp;
    try (InputStream in = new ByteArrayInputStream(ret.keystore)) {
      kp = X509KeypairWithCert.fromPKCS12Keystore(in, password, null, password,
          (X509Cert) null);
    }
    byte[] csr = new CertificationRequest.CsrBuilder(
        new X500Name("CN=" + profile + "-ra,O=myorg,C=DE"),
        kp.certChain()[0].subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(kp.getKey(), kp.publicKey()).contentSigner()).getEncoded();
    ret.cert = caManager.generateCertificate(CA, profile, csr, null, null).x509Cert();
    return ret;
  }

}
