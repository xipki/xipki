// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.PopControl;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.X509P12XdhMacSignerBuilder;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.KemHmacSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.http.HttpResponse;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Proof of possession of keys that cannot sign: DH-based POP (X25519, the MAC key agreed with
 * the static DH key of the gateway) and KEM-based POP (ML-KEM-768, the MAC key encapsulated by
 * the gateway with its KEM master key). The gateway selects its key ({@link PopControl}) and
 * verifies the CSR ({@link GatewayUtil#verifyCsr}); enrollment via REST including the
 * endpoints {@code dh-pop-certs} and {@code kem-encapkey}.
 *
 * @author Lijun Liao (xipki)
 */
public class PopH2Test {

  private static final String CT_PKCS10 = "application/pkcs10";

  private static GatewayTestEnv env;

  private static SecurityFactory securityFactory;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    securityFactory = env.ca().securities().securityFactory();
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  // ---------------------------------------------------------------- DH

  @Test
  public void dhPopCertsAreAvailable() throws Exception {
    HttpResponse resp = service("GET", "/" + GatewayTestEnv.PROFILE_KEX + "/dh-pop-certs",
        null, null);
    Assert.assertEquals(200, resp.statusCode());
    X509Cert cert = X509Util.parseCerts(resp.body()).get(0);
    Assert.assertEquals(env.dhPopCert(), cert);
  }

  @Test
  public void enrollWithDhPop() throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(KeySpec.X25519);
    CertificationRequest csr = dhCsr("CN=dhpop.example.org,O=myorg,C=DE", kp, env.dhPopCert());
    Assert.assertTrue(GatewayUtil.verifyCsr(csr, securityFactory, env.popControl()));

    X509Cert cert = enroll(csr);
    Assert.assertEquals(SubjectPublicKeyInfo.fromPublicKey(kp.getPublic()),
        cert.subjectPublicKeyInfo());
  }

  @Test
  public void dhPopWithUnknownGatewayKeyIsRejected() throws Exception {
    // the POP was computed against another static DH key
    KeyPair otherDh = KeyUtil.generateKeyPair(KeySpec.X25519);
    KeyPair issuer = KeyUtil.generateKeyPair(KeySpec.ED25519);
    Instant now = Instant.now();
    X509Cert otherCert = new X509Cert(new org.xipki.asn1.x509.Certificate.V3CertBuilder(
        new X500Name("CN=other DH POP issuer"), BigInteger.TEN, now,
        now.plus(1, ChronoUnit.DAYS), new X500Name("CN=other DH"),
        SubjectPublicKeyInfo.fromPublicKey(otherDh.getPublic()))
        .build(KeyUtil.getSigner(issuer.getPrivate(), issuer.getPublic()).contentSigner()));

    CertificationRequest csr = dhCsr("CN=dhpop-unknown.example.org,O=myorg,C=DE",
        KeyUtil.generateKeyPair(KeySpec.X25519), otherCert);
    Assert.assertFalse(GatewayUtil.verifyCsr(csr, securityFactory, env.popControl()));
    assertNotEnrolled(csr);
  }

  @Test
  public void dhPopWithoutDhKeyAtTheGateway() throws Exception {
    CertificationRequest csr = dhCsr("CN=dhpop-nokey.example.org,O=myorg,C=DE",
        KeyUtil.generateKeyPair(KeySpec.X25519), env.dhPopCert());
    PopControl noKeys = new PopControl(new GatewayConf.PopControlConf(null, null, null), null);
    Assert.assertFalse(GatewayUtil.verifyCsr(csr, securityFactory, noKeys));
  }

  // ---------------------------------------------------------------- KEM

  @Test
  public void enrollWithKemPop() throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(KeySpec.MLKEM768);
    KemEncapKey encapKey = kemEncapKey(kp);
    CertificationRequest csr = kemCsr("CN=kempop.example.org,O=myorg,C=DE", kp, encapKey,
        encapKey.id());
    Assert.assertTrue(GatewayUtil.verifyCsr(csr, securityFactory, env.popControl()));

    X509Cert cert = enroll(csr);
    Assert.assertEquals(SubjectPublicKeyInfo.fromPublicKey(kp.getPublic()),
        cert.subjectPublicKeyInfo());
  }

  @Test
  public void kemPopWithWrongMacKeyIsRejected() throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(KeySpec.MLKEM768);
    KemEncapKey encapKey = kemEncapKey(kp);
    // a MAC key other than the encapsulated one (e.g. a client without the private key)
    byte[] wrongMacKey = new byte[32];
    new SecureRandom().nextBytes(wrongMacKey);
    CertificationRequest csr = new CertificationRequest.CsrBuilder(
        new X500Name("CN=kempop-wrong.example.org,O=myorg,C=DE"),
        SubjectPublicKeyInfo.fromPublicKey(kp.getPublic()))
        .build(new KemHmacSigner(encapKey.id(),
            new SecretKeySpec(wrongMacKey, "HMAC-SHA256")).contentSigner());
    Assert.assertFalse(GatewayUtil.verifyCsr(csr, securityFactory, env.popControl()));
    assertNotEnrolled(csr);
  }

  @Test
  public void kemPopWithUnknownMasterKeyIdIsRejected() throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(KeySpec.MLKEM768);
    KemEncapKey encapKey = kemEncapKey(kp);
    CertificationRequest csr = kemCsr("CN=kempop-unknown.example.org,O=myorg,C=DE", kp,
        encapKey, "unknown-master-key");
    Assert.assertFalse(GatewayUtil.verifyCsr(csr, securityFactory, env.popControl()));
  }

  // ---------------------------------------------------------------- helpers

  /** CSR with DH-based POP: MAC with the key agreed with the given static DH key. */
  private static CertificationRequest dhCsr(String subject, KeyPair kp, X509Cert dhCert)
      throws Exception {
    ConcurrentSigner signer = new X509P12XdhMacSignerBuilder(dhCert, kp.getPrivate(),
        kp.getPublic()).createSigner(1);
    Signer signer0 = signer.borrowSigner();
    try {
      return new CertificationRequest.CsrBuilder(new X500Name(subject),
          SubjectPublicKeyInfo.fromPublicKey(kp.getPublic())).build(signer0.contentSigner());
    } finally {
      signer.requiteSigner(signer0);
    }
  }

  /** CSR with KEM-based POP: MAC with the key decapsulated from the KEM encap key. */
  private static CertificationRequest kemCsr(String subject, KeyPair kp, KemEncapKey encapKey,
                                             String id) throws Exception {
    byte[] macKey = KemUtil.mlkemDecryptSecret(kp.getPrivate(), encapKey.encapulation());
    return new CertificationRequest.CsrBuilder(new X500Name(subject),
        SubjectPublicKeyInfo.fromPublicKey(kp.getPublic()))
        .build(new KemHmacSigner(id, new SecretKeySpec(macKey, "HMAC-SHA256")).contentSigner());
  }

  /** The KEM encap key for the public key, from the gateway (REST kem-encapkey). */
  private static KemEncapKey kemEncapKey(KeyPair kp) throws Exception {
    HttpResponse resp = service("POST", "/" + GatewayTestEnv.PROFILE_KEX + "/kem-encapkey",
        "application/octet-stream",
        SubjectPublicKeyInfo.fromPublicKey(kp.getPublic()).getEncoded());
    Assert.assertEquals(200, resp.statusCode());
    return KemEncapKey.decode(resp.body());
  }

  private static X509Cert enroll(CertificationRequest csr) throws Exception {
    HttpResponse resp = service("POST", "/" + GatewayTestEnv.PROFILE_KEX + "/enroll-cert",
        CT_PKCS10, csr.getEncoded());
    Assert.assertEquals(new String(resp.body() == null ? new byte[0] : resp.body(),
        StandardCharsets.UTF_8), 200, resp.statusCode());
    return X509Util.parseCert(resp.body());
  }

  private static void assertNotEnrolled(CertificationRequest csr) throws Exception {
    HttpResponse resp = service("POST", "/" + GatewayTestEnv.PROFILE_KEX + "/enroll-cert",
        CT_PKCS10, csr.getEncoded());
    Assert.assertNotEquals(200, resp.statusCode());
  }

  private static HttpResponse service(String method, String path, String contentType,
                                      byte[] body) {
    TestHttpRequest req = new TestHttpRequest(method).header("Authorization",
        GatewayTestEnv.basicAuth(GatewayTestEnv.USER, GatewayTestEnv.PASSWORD));
    if (contentType != null) {
      req.header("Content-Type", contentType);
    }
    return env.restResponder().service(path, body, req, new AuditEvent("test"));
  }

}
