/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs12;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignatureSigner;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;

/**
 * PKCS#12 key generator.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P12KeyGenerator {

  private static class KeyPairWithSubjectPublicKeyInfo {

    private KeyPair keypair;

    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    KeyPairWithSubjectPublicKeyInfo(KeyPair keypair, SubjectPublicKeyInfo subjectPublicKeyInfo)
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

  private static class KeyAndCertPair {

    private final X509Certificate jceCert;

    private final PrivateKey key;

    KeyAndCertPair(X509CertificateHolder cert, PrivateKey key) throws CertificateException {
      this.key = key;
      this.jceCert = X509Util.toX509Cert(cert.toASN1Structure());
    }

  } // class KeyAndCertPair

  private static final long MIN = 60L * 1000;

  private static final long DAY = 24L * 60 * 60 * 1000;

  public P12KeyGenerator() throws Exception {
  }

  // CHECKSTYLE:SKIP
  public P12KeyGenerationResult generateRSAKeypair(int keysize, BigInteger publicExponent,
      KeystoreGenerationParameters params, String selfSignedCertSubject) throws Exception {
    KeyPairWithSubjectPublicKeyInfo kp = genRSAKeypair(keysize, publicExponent, params.getRandom());
    return generateIdentity(kp, params, selfSignedCertSubject);
  }

  // CHECKSTYLE:SKIP
  public P12KeyGenerationResult generateDSAKeypair(int plength, int qlength,
      KeystoreGenerationParameters params, String selfSignedCertSubject) throws Exception {
    KeyPairWithSubjectPublicKeyInfo kp = genDSAKeypair(plength, qlength, params.getRandom());
    return generateIdentity(kp, params, selfSignedCertSubject);
  }

  // CHECKSTYLE:SKIP
  public P12KeyGenerationResult generateECKeypair(ASN1ObjectIdentifier curveOid,
      KeystoreGenerationParameters params, String selfSignedCertSubject) throws Exception {
    Args.notNull(curveOid, "curveOid");
    KeyPair keypair = KeyUtil.generateECKeypair(curveOid, params.getRandom());
    AlgorithmIdentifier algId = new AlgorithmIdentifier(
        X9ObjectIdentifiers.id_ecPublicKey, curveOid);

    ECPublicKey pub = (ECPublicKey) keypair.getPublic();
    int orderBitLength = pub.getParams().getOrder().bitLength();
    byte[] keyData = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), orderBitLength);
    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algId, keyData);

    return generateIdentity(new KeyPairWithSubjectPublicKeyInfo(keypair, subjectPublicKeyInfo),
        params, selfSignedCertSubject);
  } // method generateECKeypair

  // CHECKSTYLE:SKIP
  public P12KeyGenerationResult generateEdECKeypair(ASN1ObjectIdentifier curveOid,
      KeystoreGenerationParameters params, String selfSignedCertSubject) throws Exception {
    Args.notNull(curveOid, "curveOid");
    if (!EdECConstants.isEdwardsOrMontgomeryCurve(curveOid)) {
      throw new IllegalArgumentException("invalid EdDSA curve  " + curveOid.getId());
    }
    KeyPair keypair = KeyUtil.generateEdECKeypair(curveOid, params.getRandom());
    SubjectPublicKeyInfo subjectPublicKeyInfo =
        KeyUtil.createSubjectPublicKeyInfo(keypair.getPublic());

    return generateIdentity(new KeyPairWithSubjectPublicKeyInfo(keypair, subjectPublicKeyInfo),
        params, selfSignedCertSubject);
  } // method generateEdECKeypair

  public P12KeyGenerationResult generateSecretKey(String algorithm, int keyBitLen,
      KeystoreGenerationParameters params) throws Exception {
    if (keyBitLen % 8 != 0) {
      throw new IllegalArgumentException("keyBitLen (" + keyBitLen + ") must be multiple of 8");
    }

    SecureRandom random = params.getRandom();
    if (random == null) {
      random = new SecureRandom();
    }

    byte[] keyValue = new byte[keyBitLen / 8];
    random.nextBytes(keyValue);
    SecretKey secretKey = new SecretKeySpec(keyValue, algorithm);

    KeyStore ks = KeyUtil.getKeyStore("JCEKS");
    ks.load(null, params.getPassword());

    ks.setKeyEntry("main", secretKey, params.getPassword(), null);

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.getPassword());
    } finally {
      ksStream.flush();
    }

    P12KeyGenerationResult result = new P12KeyGenerationResult(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    return result;
  } // method generateSecretKey

  // CHECKSTYLE:SKIP
  private KeyPairWithSubjectPublicKeyInfo genRSAKeypair(int keysize,
      BigInteger publicExponent, SecureRandom random) throws Exception {
    KeyPair kp = KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
    java.security.interfaces.RSAPublicKey rsaPubKey =
        (java.security.interfaces.RSAPublicKey) kp.getPublic();

    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
        new RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));
    return new KeyPairWithSubjectPublicKeyInfo(kp, spki);
  } // method genRSAKeypair

  // CHECKSTYLE:SKIP
  private KeyPairWithSubjectPublicKeyInfo genDSAKeypair(int plength, int qlength,
      SecureRandom random) throws Exception {
    KeyPair kp = KeyUtil.generateDSAKeypair(plength, qlength, random);
    SubjectPublicKeyInfo spki = KeyUtil.createSubjectPublicKeyInfo((DSAPublicKey) kp.getPublic());
    return new KeyPairWithSubjectPublicKeyInfo(kp, spki);
  }

  private static P12KeyGenerationResult generateIdentity(KeyPairWithSubjectPublicKeyInfo kp,
      KeystoreGenerationParameters params, String selfSignedCertSubject) throws Exception {
    Date now = new Date();
    Date notBefore = new Date(now.getTime() - 10 * MIN); // 10 minutes past
    Date notAfter = new Date(notBefore.getTime() + 3650 * DAY);

    String dnStr = (selfSignedCertSubject == null) ? "CN=DUMMY" : selfSignedCertSubject;
    X500Name subjectDn = new X500Name(dnStr);
    SubjectPublicKeyInfo subjectPublicKeyInfo = kp.getSubjectPublicKeyInfo();
    ContentSigner contentSigner = getContentSigner(kp.getKeypair().getPrivate());

    // Generate keystore
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(subjectDn,
        BigInteger.ONE, notBefore, notAfter, subjectDn, subjectPublicKeyInfo);

    KeyAndCertPair identity = new KeyAndCertPair(certGenerator.build(contentSigner),
        kp.getKeypair().getPrivate());

    KeyStore ks = KeyUtil.getKeyStore("PKCS12");
    ks.load(null, params.getPassword());

    ks.setKeyEntry("main", identity.key, params.getPassword(),
        new Certificate[]{identity.jceCert});

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.getPassword());
    } finally {
      ksStream.flush();
    }

    P12KeyGenerationResult result = new P12KeyGenerationResult(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    return result;
  } // method generateIdentity

  private static ContentSigner getContentSigner(PrivateKey key) throws Exception {
    BcContentSignerBuilder builder;

    if (key instanceof RSAPrivateKey) {
      ASN1ObjectIdentifier hashOid = X509ObjectIdentifiers.id_SHA1;
      ASN1ObjectIdentifier sigOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;

      builder = new BcRSAContentSignerBuilder(buildAlgId(sigOid), buildAlgId(hashOid));
    } else if (key instanceof DSAPrivateKey) {
      ASN1ObjectIdentifier hashOid = X509ObjectIdentifiers.id_SHA1;
      AlgorithmIdentifier sigId = new AlgorithmIdentifier(
          X9ObjectIdentifiers.id_dsa_with_sha1);

      builder = new BcDSAContentSignerBuilder(sigId, buildAlgId(hashOid));
    } else if (key instanceof ECPrivateKey) {
      HashAlgo hashAlgo;
      ASN1ObjectIdentifier sigOid;

      int keysize = ((ECPrivateKey) key).getParams().getOrder().bitLength();
      if (keysize > 384) {
        hashAlgo = HashAlgo.SHA512;
        sigOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
      } else if (keysize > 256) {
        hashAlgo = HashAlgo.SHA384;
        sigOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
      } else if (keysize > 224) {
        hashAlgo = HashAlgo.SHA224;
        sigOid = X9ObjectIdentifiers.ecdsa_with_SHA224;
      } else if (keysize > 160) {
        hashAlgo = HashAlgo.SHA256;
        sigOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
      } else {
        hashAlgo = HashAlgo.SHA1;
        sigOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
      }

      builder = new BcECContentSignerBuilder(new AlgorithmIdentifier(sigOid),
          buildAlgId(hashAlgo.getOid()));
    } else if (key instanceof EdDSAKey) {
      String algorithm = key.getAlgorithm();
      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(algorithm);
      if (curveOid == null || !EdECConstants.isEdwardsCurve(curveOid)) {
        throw new InvalidKeyException("unknown EdDSA key algorithm " + algorithm);
      }
      Signature signer = Signature.getInstance("EdDSA", "BC");

      return new SignatureSigner(new AlgorithmIdentifier(curveOid), signer, key);
    } else if (key instanceof XDHKey) {
      String algorithm = key.getAlgorithm();
      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(algorithm);
      if (curveOid == null || !EdECConstants.isMontgomeryCurve(curveOid)) {
        throw new InvalidKeyException("unknown XDH key algorithm " + algorithm);
      }
      Signature signer = Signature.getInstance("EdDSA", "BC");

      // Just dummy: signature created by the signKey cannot be verified by the public key.
      PrivateKey signKey = KeyUtil.convertXDHToDummyEdDSAPrivateKey(key);
      return new SignatureSigner(new AlgorithmIdentifier(curveOid), signer, signKey);
    } else {
      throw new IllegalArgumentException("unknown type of key " + key.getClass().getName());
    }

    return builder.build(KeyUtil.generatePrivateKeyParameter(key));
  } // method getContentSigner

  private static AlgorithmIdentifier buildAlgId(ASN1ObjectIdentifier identifier) {
    return new AlgorithmIdentifier(identifier, DERNull.INSTANCE);
  }

}
