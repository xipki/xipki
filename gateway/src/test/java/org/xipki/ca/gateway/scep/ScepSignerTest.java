// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.KeyUsage;
import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.GatewayConf;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.pkcs12.KeypairWithCert;
import org.xipki.pkix.pkcs12.P12ContentSignerBuilder;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.SignatureSigner;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.codec.exception.InvalidConfException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

/**
 * Tests of {@link ScepSigner} and {@link CaNameScepSigners} with separate decryption key.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepSignerTest {

  private static final SecureRandom RND = new SecureRandom();

  private static KeyPair signKp;

  private static KeyPair encKp;

  @BeforeClass
  public static void init() throws Exception {
    signKp = KeyUtil.generateKeyPair(KeySpec.RSA2048, RND);
    encKp = KeyUtil.generateKeyPair(KeySpec.RSA2048, RND);
  }

  @Test
  public void testWithoutDecryptor() throws Exception {
    ScepSigner signer = new ScepSigner(signer(signKp,
        cert(signKp, "CN=RA", KeyUsage.digitalSignature, KeyUsage.keyEncipherment)));
    Assert.assertSame(signer.cert(), signer.encryptionCert());
  }

  @Test
  public void testWithDecryptor() throws Exception {
    X509Cert encCert = cert(encKp, "CN=RA-ENC", KeyUsage.keyEncipherment);
    ScepSigner signer = new ScepSigner(
        signer(signKp, cert(signKp, "CN=RA", KeyUsage.digitalSignature)),
        new KeypairWithCert(encKp.getPrivate(), new X509Cert[]{encCert}));
    Assert.assertEquals(encCert, signer.encryptionCert());
    Assert.assertNotEquals(signer.cert(), signer.encryptionCert());
  }

  @Test
  public void testInvalidKeyUsages() throws Exception {
    ConcurrentSigner goodSigner = signer(signKp, cert(signKp, "CN=RA", KeyUsage.digitalSignature));
    ConcurrentSigner badSigner = signer(signKp,
        cert(signKp, "CN=RA", KeyUsage.digitalSignature, KeyUsage.keyEncipherment));
    X509Cert goodEncCert = cert(encKp, "CN=RA-ENC", KeyUsage.keyEncipherment);
    X509Cert badEncCert = cert(encKp, "CN=RA-ENC",
        KeyUsage.keyEncipherment, KeyUsage.digitalSignature);

    assertInvalid(badSigner, new KeypairWithCert(encKp.getPrivate(),
        new X509Cert[]{goodEncCert}), "signer certificate");
    assertInvalid(goodSigner, new KeypairWithCert(encKp.getPrivate(),
        new X509Cert[]{badEncCert}), "decryptor certificate");
    // decryption key does not match the certificate
    assertInvalid(goodSigner, new KeypairWithCert(signKp.getPrivate(),
        new X509Cert[]{goodEncCert}), "does not match");
    // same key
    assertInvalid(goodSigner, new KeypairWithCert(signKp.getPrivate(),
        new X509Cert[]{cert(signKp, "CN=RA-ENC", KeyUsage.keyEncipherment)}), "signing key");
  }

  @Test
  public void testCaNameScepSigners() throws Exception {
    ConcurrentSigner raSigner =
        signer(signKp, cert(signKp, "CN=RA", KeyUsage.digitalSignature));
    X509Cert encCert = cert(encKp, "CN=RA-ENC", KeyUsage.keyEncipherment);

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.setKeyEntry("main", PrivateKeyInfo.fromEncoded(encKp.getPrivate().getEncoded()),
        encCert.getCert());
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    ks.store(bout, "CHANGEIT".toCharArray());

    GatewayConf.SignerConf decryptorConf = new GatewayConf.SignerConf("pkcs12",
        "password=CHANGEIT,keystore=base64:" + Base64.encodeToString(bout.toByteArray()), null);
    ScepProtocolConf.CaNameDecryptorsConf decryptorsConf =
        new ScepProtocolConf.CaNameDecryptorsConf(null, List.of(
            new ScepProtocolConf.CaNameDecryptorConf(decryptorConf, List.of("SubCA"))));

    // signer as default, decryptor for subca only
    CaNameScepSigners signers = new CaNameScepSigners(
        new CaNameSigners(raSigner, null), decryptorsConf);
    Assert.assertEquals(encCert, signers.getSigner("subca").encryptionCert());
    ScepSigner other = signers.getSigner("other");
    Assert.assertSame(other.cert(), other.encryptionCert());

    // decryptor for a CA without signer
    try {
      new CaNameScepSigners(new CaNameSigners(null, Map.of("other", raSigner)), decryptorsConf);
      Assert.fail("InvalidConfException expected");
    } catch (InvalidConfException ex) {
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("no signer"));
    }
  }

  private static void assertInvalid(
      ConcurrentSigner signer, KeypairWithCert decryptor, String expMessage) {
    try {
      new ScepSigner(signer, decryptor);
      Assert.fail("IllegalArgumentException expected");
    } catch (IllegalArgumentException ex) {
      Assert.assertTrue(ex.getMessage(), ex.getMessage().contains(expMessage));
    }
  }

  private static ConcurrentSigner signer(KeyPair kp, X509Cert cert) throws Exception {
    return new P12ContentSignerBuilder(new KeypairWithCert(kp.getPrivate(), new X509Cert[]{cert}))
        .createSigner(SignAlgo.RSA_SHA256, 1, RND);
  }

  private static X509Cert cert(KeyPair kp, String subject, KeyUsage... usages) throws Exception {
    X500Name name = new X500Name(subject);
    Instant notBefore = Instant.now().minus(5, ChronoUnit.MINUTES);
    Certificate.V3CertBuilder builder = new Certificate.V3CertBuilder(name, BigInteger.ONE,
        notBefore, notBefore.plus(1, ChronoUnit.DAYS), name,
        SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded()));
    builder.addExtension(Extension.ofKeyUsage(true, new KeyUsage(usages)));
    return new X509Cert(builder.build(
        SignatureSigner.newContentSigner(SignAlgo.RSA_SHA256, kp.getPrivate())));
  }

}
