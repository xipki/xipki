// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x500.X500Name;
import org.xipki.ca.sdk.*;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.KeyCertBytesPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;

/**
 * The SDK client ({@link SdkClient}) directly against the SDK interface of the CA: every
 * command, the per-entry errors and the mapping of the error responses to
 * {@link SdkErrorResponseException}.
 *
 * @author Lijun Liao (xipki)
 */
public class SdkClientTest {

  private static final String CA = GatewayTestEnv.CA;

  private static final String PROFILE = GatewayTestEnv.PROFILE;

  private static GatewayTestEnv env;

  private static SdkClient sdk;

  private static X509Cert caCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    sdk = env.sdk();
    caCert = env.ca().caCert();
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  // ---------------------------------------------------------------- CA information

  @Test
  public void caInformation() throws Exception {
    Assert.assertTrue(sdk.healthy(CA));
    Assert.assertArrayEquals(caCert.getEncoded(), sdk.cacert(CA));
    byte[][] chain = sdk.cacerts(CA);
    Assert.assertArrayEquals(caCert.getEncoded(), chain[0]);

    byte[] subject = caCert.subject().getEncoded();
    Assert.assertArrayEquals(caCert.getEncoded(), sdk.cacertBySubject(subject));
    Assert.assertArrayEquals(caCert.getEncoded(), sdk.cacertsBySubject(subject)[0]);
    CaNameResponse name = sdk.caNameBySubject(subject);
    Assert.assertEquals(CA, name.name());

    CertprofileInfoResponse profile = sdk.profileInfo(CA, PROFILE);
    Assert.assertNotNull(profile.keyTypes());
    Assert.assertTrue(profile.keyTypes().length > 0);
  }

  @Test
  public void unknownCa() {
    Assert.assertFalse(sdk.healthy("unknown-ca"));
    assertError(ErrorCode.PATH_NOT_FOUND, () -> sdk.cacert("unknown-ca"));
  }

  @Test
  public void errorOfTheCaIsPassedOn() {
    assertError(ErrorCode.UNKNOWN_CERT_PROFILE, () -> sdk.enrollCertCaGenKeypair(CA,
        "unknown-profile", "CN=sdk-unknown.example.org,O=myorg,C=DE"));
    assertError(ErrorCode.UNKNOWN_CERT_PROFILE, () -> sdk.enrollCert(CA, "unknown-profile",
        GatewayTestEnv.newCsr("CN=sdk-unknown.example.org,O=myorg,C=DE")));
  }

  @Test
  public void caNotReachable() throws Exception {
    int port;
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      port = socket.getLocalPort();
    }
    SdkClient offline = new SdkClient("http://127.0.0.1:" + port + "/ra/", null, null);
    Assert.assertFalse(offline.healthy(CA));
    assertError(ErrorCode.SYSTEM_UNAVAILABLE, () -> offline.cacert(CA));
  }

  // ---------------------------------------------------------------- enrollment

  @Test
  public void enrollWithCsrAndReenroll() throws Exception {
    X509Cert cert = X509Util.parseCert(sdk.enrollCert(CA, PROFILE,
        GatewayTestEnv.newCsr("CN=sdk-csr.example.org,O=myorg,C=DE")));
    Assert.assertEquals(caCert.subject(), cert.issuer());

    X509Cert renewed = X509Util.parseCert(sdk.reenrollCert(CA, PROFILE,
        GatewayTestEnv.newCsr("CN=sdk-csr.example.org,O=myorg,C=DE"),
        caCert.subject(), cert.serialNumber()));
    Assert.assertNotEquals(cert.serialNumber(), renewed.serialNumber());
    Assert.assertEquals(cert.subject(), renewed.subject());

    // the certificate is available via get_cert
    Assert.assertArrayEquals(renewed.getEncoded(),
        sdk.getCert(CA, caCert.subject(), renewed.serialNumber()));
  }

  @Test
  public void enrollWithKeyGeneratedByTheCa() throws Exception {
    KeyCertBytesPair keyCert = sdk.enrollCertCaGenKeypair(CA, PROFILE,
        "CN=sdk-genkey.example.org,O=myorg,C=DE");
    Assert.assertNotNull(keyCert.key());
    X509Cert cert = X509Util.parseCert(keyCert.cert());

    KeyCertBytesPair renewed = sdk.reenrollCertCaGenKeypair(CA, PROFILE, cert.subject(),
        caCert.subjectText(), cert.serialNumber());
    Assert.assertNotNull(renewed.key());
    Assert.assertNotEquals(cert.publicKey(), X509Util.parseCert(renewed.cert()).publicKey());
  }

  @Test
  public void reenrollWithKeyGeneratedByTheCaChecksTheOldCertificate() throws Exception {
    assertError(ErrorCode.UNKNOWN_CERT, () -> sdk.reenrollCertCaGenKeypair(CA, PROFILE,
        new X500Name("CN=sdk-renew-unknown.example.org,O=myorg,C=DE"), caCert.subjectText(),
        BigInteger.valueOf(0x7fffffffL)));

    BigInteger revoked = issue("sdk-renew-revoked-genkey.example.org");
    env.ca().caManager().revokeCertificate(CA, revoked, CrlReason.KEY_COMPROMISE, null);
    assertError(ErrorCode.CERT_REVOKED, () -> sdk.reenrollCertCaGenKeypair(CA, PROFILE,
        new X500Name("CN=sdk-renew-revoked-genkey.example.org,O=myorg,C=DE"),
        caCert.subjectText(), revoked));
  }

  @Test
  public void reenrollWithCsrChecksTheOldCertificate() throws Exception {
    assertError(ErrorCode.UNKNOWN_CERT, () -> sdk.reenrollCert(CA, PROFILE,
        GatewayTestEnv.newCsr("CN=sdk-renew-unknown.example.org,O=myorg,C=DE"),
        caCert.subject(), BigInteger.valueOf(0x7fffffffL)));

    BigInteger revoked = issue("sdk-renew-revoked.example.org");
    env.ca().caManager().revokeCertificate(CA, revoked, CrlReason.KEY_COMPROMISE, null);
    assertError(ErrorCode.CERT_REVOKED, () -> sdk.reenrollCert(CA, PROFILE,
        GatewayTestEnv.newCsr("CN=sdk-renew-revoked.example.org,O=myorg,C=DE"),
        caCert.subject(), revoked));

    // issuer of another CA
    BigInteger good = issue("sdk-renew-other-issuer.example.org");
    assertError(ErrorCode.UNKNOWN_CERT, () -> sdk.reenrollCert(CA, PROFILE,
        GatewayTestEnv.newCsr("CN=sdk-renew-other-issuer.example.org,O=myorg,C=DE"),
        new X500Name("CN=other CA,C=DE"), good));
  }

  // ---------------------------------------------------------------- revocation

  @Test
  public void revokeUnsuspendAndRemove() throws Exception {
    BigInteger onHold = issue("sdk-hold.example.org");
    BigInteger revoked = issue("sdk-revoked.example.org");
    BigInteger unknown = BigInteger.valueOf(0x7ffffffeL);

    // the CA is identified by SHA-1 fingerprint, name and key identifier
    RevokeCertsResponse resp = sdk.revokeCerts(new RevokeCertsRequest(
        HashAlgo.SHA1.hash(caCert.getEncoded()), issuer(), caCert.subjectKeyId(),
        new RevokeCertsRequest.Entry[]{
            new RevokeCertsRequest.Entry(onHold, CrlReason.CERTIFICATE_HOLD, null),
            new RevokeCertsRequest.Entry(revoked, CrlReason.KEY_COMPROMISE, null),
            new RevokeCertsRequest.Entry(unknown, CrlReason.KEY_COMPROMISE, null)}));
    assertEntries(resp.entries(), null, null, ErrorCode.UNKNOWN_CERT);
    Assert.assertTrue(env.ca().caManager().getCert(CA, revoked).isRevoked());

    // the CA identified only by its name
    UnSuspendOrRemoveCertsResponse unsuspended = sdk.unsuspendCerts(
        new UnsuspendOrRemoveCertsRequest(null, issuer(), null,
            new BigInteger[]{onHold, revoked}));
    // only certificates on hold can be unsuspended
    assertEntries(unsuspended.entries(), null, ErrorCode.NOT_PERMITTED);
    Assert.assertFalse(env.ca().caManager().getCert(CA, onHold).isRevoked());

    UnSuspendOrRemoveCertsResponse removed = sdk.removeCerts(
        new UnsuspendOrRemoveCertsRequest(null, issuer(), null,
            new BigInteger[]{revoked, unknown}));
    assertEntries(removed.entries(), null, ErrorCode.UNKNOWN_CERT);
    Assert.assertNull(env.ca().caManager().getCert(CA, revoked));
  }

  @Test
  public void revokeAtUnknownCa() {
    assertError(ErrorCode.PATH_NOT_FOUND, () -> sdk.revokeCerts(new RevokeCertsRequest(
        null, new NameType("CN=unknown CA,C=DE"), null, new RevokeCertsRequest.Entry[]{
            new RevokeCertsRequest.Entry(BigInteger.ONE, CrlReason.KEY_COMPROMISE, null)})));
  }

  // ---------------------------------------------------------------- CRL

  @Test
  public void crl() throws Exception {
    byte[] generated = sdk.generateCrl(CA, null);
    Assert.assertNotNull(generated);
    Assert.assertArrayEquals(generated, sdk.currentCrl(CA));
    Assert.assertNotNull(sdk.currentCrlInfo(CA));
  }

  // ---------------------------------------------------------------- helpers

  private interface SdkCall {
    void call() throws Exception;
  }

  private static void assertError(ErrorCode expected, SdkCall call) {
    SdkErrorResponseException ex = Assert.assertThrows(SdkErrorResponseException.class,
        call::call);
    Assert.assertEquals(ex.errorResponse().message(), expected, ex.errorResponse().code());
  }

  /** Each expected code: null for success. */
  private static void assertEntries(SingleCertSerialEntry[] entries, ErrorCode... expected) {
    Assert.assertEquals(expected.length, entries.length);
    for (int i = 0; i < expected.length; i++) {
      if (expected[i] == null) {
        Assert.assertNull("entry " + i, entries[i].error());
      } else {
        Assert.assertNotNull("entry " + i, entries[i].error());
        Assert.assertEquals("entry " + i + ": " + entries[i].error().message(),
            expected[i].code(), entries[i].error().code());
      }
    }
  }

  private static NameType issuer() {
    return new NameType(caCert.subject());
  }

  private static BigInteger issue(String commonName) throws Exception {
    return X509Util.parseCert(sdk.enrollCertCaGenKeypair(CA, PROFILE,
        "CN=" + commonName + ",O=myorg,C=DE").cert()).serialNumber();
  }

}
