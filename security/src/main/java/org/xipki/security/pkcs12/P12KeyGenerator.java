// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignatureSigner;
import org.xipki.security.X509Cert;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.RandomUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * PKCS#12 key generator.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P12KeyGenerator {

  public static class KeyPairWithSubjectPublicKeyInfo {

    private final KeyPair keypair;

    private final SubjectPublicKeyInfo subjectPublicKeyInfo;

    public KeyPairWithSubjectPublicKeyInfo(KeyPair keypair, SubjectPublicKeyInfo subjectPublicKeyInfo)
        throws InvalidKeySpecException {
      super();
      this.keypair = keypair;
      this.subjectPublicKeyInfo = X509Util.toRfc3279Style(subjectPublicKeyInfo);
    }

    public KeyPair getKeypair() {
      return keypair;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
      return subjectPublicKeyInfo;
    }

  } // class KeyPairWithSubjectPublicKeyInfo

  public static class KeyAndCertPair {

    private final X509Cert cert;

    private final PrivateKey key;

    public KeyAndCertPair(X509Cert cert, PrivateKey key) {
      this.key = key;
      this.cert = cert;
    }

    public X509Cert getCert() {
      return cert;
    }

    public PrivateKey getKey() {
      return key;
    }
  } // class KeyAndCertPair

  public P12KeyGenerator() {
  }

  public static KeyStoreWrapper generateRSAKeypair(
      int keysize, BigInteger publicExponent, KeystoreGenerationParameters params, String selfSignedCertSubject)
      throws Exception {
    KeyPairWithSubjectPublicKeyInfo kp = genRSAKeypair(keysize, publicExponent, params.getRandom());
    return generateIdentity(kp, params, selfSignedCertSubject);
  }

  public static KeyStoreWrapper generateDSAKeypair(
      int plength, int qlength, KeystoreGenerationParameters params, String selfSignedCertSubject)
      throws Exception {
    KeyPairWithSubjectPublicKeyInfo kp = genDSAKeypair(plength, qlength, params.getRandom());
    return generateIdentity(kp, params, selfSignedCertSubject);
  }

  public static KeyStoreWrapper generateECKeypair(
      ASN1ObjectIdentifier curveOid, KeystoreGenerationParameters params, String selfSignedCertSubject)
      throws Exception {
    KeyPairWithSubjectPublicKeyInfo keyInfo = genECKeypair(curveOid, params.getRandom());
    return generateIdentity(keyInfo, params, selfSignedCertSubject);
  } // method generateECKeypair

  public static KeyStoreWrapper generateEdECKeypair(
      ASN1ObjectIdentifier curveOid, KeystoreGenerationParameters params, String selfSignedCertSubject)
      throws Exception {
    KeyPairWithSubjectPublicKeyInfo keyInfo = genEdECKeypair(curveOid, params.getRandom());
    return generateIdentity(keyInfo, params, selfSignedCertSubject);
  }

  public static KeyStoreWrapper generateSecretKey(String algorithm, int keyBitLen, KeystoreGenerationParameters params)
      throws Exception {
    if (keyBitLen % 8 != 0) {
      throw new IllegalArgumentException("keyBitLen (" + keyBitLen + ") must be multiple of 8");
    }

    SecureRandom random = params.getRandom();
    byte[] keyValue;
    if (random == null) {
      keyValue = RandomUtil.nextBytes(keyBitLen / 8);
    } else {
      keyValue = new byte[keyBitLen / 8];
      random.nextBytes(keyValue);
    }

    SecretKey secretKey = new SecretKeySpec(keyValue, algorithm);

    KeyStore ks = KeyUtil.getOutKeyStore("JCEKS");
    ks.load(null, params.getPassword());

    ks.setKeyEntry("main", secretKey, params.getPassword(), null);

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.getPassword());
    } finally {
      ksStream.flush();
    }

    KeyStoreWrapper result = new KeyStoreWrapper(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    return result;
  }

  public static KeyPairWithSubjectPublicKeyInfo genRSAKeypair(
      int keysize, BigInteger publicExponent, SecureRandom random)
      throws Exception {
    KeyPair kp = KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
    java.security.interfaces.RSAPublicKey rsaPubKey = (java.security.interfaces.RSAPublicKey) kp.getPublic();

    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
        new RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));
    return new KeyPairWithSubjectPublicKeyInfo(kp, spki);
  }

  public static KeyPairWithSubjectPublicKeyInfo genDSAKeypair(int plength, int qlength, SecureRandom random)
      throws Exception {
    KeyPair kp = KeyUtil.generateDSAKeypair(plength, qlength, random);
    SubjectPublicKeyInfo spki = KeyUtil.createSubjectPublicKeyInfo(kp.getPublic());
    return new KeyPairWithSubjectPublicKeyInfo(kp, spki);
  }

  public static KeyPairWithSubjectPublicKeyInfo genECKeypair(
      ASN1ObjectIdentifier curveOid, SecureRandom random) throws Exception {
    KeyPair keypair = KeyUtil.generateECKeypair(Args.notNull(curveOid, "curveOid"), random);
    AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid);

    ECPublicKey pub = (ECPublicKey) keypair.getPublic();
    int fieldBitSize = pub.getParams().getCurve().getField().getFieldSize();
    byte[] keyData = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), fieldBitSize);
    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algId, keyData);

    return new KeyPairWithSubjectPublicKeyInfo(keypair, subjectPublicKeyInfo);
  } // method generateECKeypair

  public static KeyPairWithSubjectPublicKeyInfo genEdECKeypair(
      ASN1ObjectIdentifier curveOid, SecureRandom random) throws Exception {
    if (!EdECConstants.isEdwardsOrMontgomeryCurve(Args.notNull(curveOid, "curveOid"))) {
      throw new IllegalArgumentException("invalid EdDSA curve  " + curveOid.getId());
    }
    KeyPair keypair = KeyUtil.generateEdECKeypair(curveOid, random);
    SubjectPublicKeyInfo subjectPublicKeyInfo = KeyUtil.createSubjectPublicKeyInfo(keypair.getPublic());

    return new KeyPairWithSubjectPublicKeyInfo(keypair, subjectPublicKeyInfo);
  }

  private static KeyStoreWrapper generateIdentity(
      KeyPairWithSubjectPublicKeyInfo kp, KeystoreGenerationParameters params, String selfSignedCertSubject)
      throws Exception {
    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES); // 10 minutes past
    Instant notAfter = notBefore.plus(3650, ChronoUnit.DAYS);

    String dnStr = (selfSignedCertSubject == null) ? "CN=DUMMY" : selfSignedCertSubject;
    X500Name subjectDn = new X500Name(dnStr);
    SubjectPublicKeyInfo subjectPublicKeyInfo = kp.getSubjectPublicKeyInfo();
    ContentSigner contentSigner = getContentSigner(kp.getKeypair().getPrivate(), kp.getKeypair().getPublic());

    // Generate keystore
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(subjectDn, BigInteger.ONE,
        Date.from(notBefore), Date.from(notAfter), subjectDn, subjectPublicKeyInfo);

    byte[] encodedSpki = kp.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    byte[] skiValue = HashAlgo.SHA1.hash(encodedSpki);
    certGenerator.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(skiValue));
    certGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    certGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    certGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
        new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}));

    KeyAndCertPair identity = new KeyAndCertPair(
        new X509Cert(certGenerator.build(contentSigner)), kp.getKeypair().getPrivate());

    KeyStore ks = KeyUtil.getOutKeyStore("PKCS12");
    ks.load(null, params.getPassword());

    ks.setKeyEntry("main", identity.key, params.getPassword(), new Certificate[]{identity.cert.toJceCert()});

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.getPassword());
    } finally {
      ksStream.flush();
    }

    KeyStoreWrapper result = new KeyStoreWrapper(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    return result;
  } // method generateIdentity

  public static ContentSigner getContentSigner(PrivateKey key, PublicKey publicKey) throws Exception {
    SignAlgo algo;
    if (key instanceof RSAPrivateKey) {
      algo = SignAlgo.RSAPSS_SHA256;
    } else if (key instanceof DSAPrivateKey) {
      algo = SignAlgo.DSA_SHA256;
    } else if (key instanceof ECPrivateKey) {
      if (GMUtil.isSm2primev2Curve(((ECPublicKey) publicKey).getParams().getCurve())) {
        algo = SignAlgo.SM2_SM3;
      } else {
        int orderBitLength = ((ECPrivateKey) key).getParams().getOrder().bitLength();
        algo = orderBitLength > 384 ? SignAlgo.ECDSA_SHA512
            : orderBitLength > 256 ? SignAlgo.ECDSA_SHA384
            : orderBitLength > 160 ? SignAlgo.ECDSA_SHA256
            : SignAlgo.ECDSA_SHA1;
      }
    } else {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      ASN1ObjectIdentifier algOid = spki.getAlgorithm().getAlgorithm();
      if (EdECConstants.isMontgomeryCurve(algOid)) {
        Signature signer = Signature.getInstance("EdDSA", "BC");
        // Just dummy: signature created by the signKey cannot be verified by the public key.
        PrivateKey signKey = KeyUtil.convertXDHToDummyEdDSAPrivateKey(key);
        return new SignatureSigner(new AlgorithmIdentifier(algOid), signer, signKey);
      } else if (EdECConstants.isEdwardsCurve(algOid)) {
        if (EdECConstants.id_ED25519.equals(algOid)) {
          algo = SignAlgo.ED25519;
        } else { // if (EdECConstants.id_ED448.equals(curveOid)) {
          algo = SignAlgo.ED448;
        }
      } else {
        throw new IllegalArgumentException("unknown public key algorithm " + algOid.getId());
      }
    }

    P12ContentSignerBuilder builder = new P12ContentSignerBuilder(key, publicKey);
    ConcurrentContentSigner csigner = builder.createSigner(algo, 1, null);
    return csigner.borrowSigner();
  } // method getContentSigner

}
