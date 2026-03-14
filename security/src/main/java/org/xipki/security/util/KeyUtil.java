// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.util.BigIntegers;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyPairBytes;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.bridge.*;
import org.xipki.security.composite.CompositeKeyInfoConverter;
import org.xipki.security.composite.CompositeMLDSAPrivateKey;
import org.xipki.security.composite.CompositeMLDSAPublicKey;
import org.xipki.security.composite.CompositeMLKEMPrivateKey;
import org.xipki.security.composite.CompositeMLKEMPublicKey;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs12.KeyPairWithSubjectPublicKeyInfo;
import org.xipki.security.pkcs12.KeyStoreWrapper;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12ContentSignerBuilder;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkcs12.PKCS12KeyStoreWrapper;
import org.xipki.security.pkix.DHSigStaticKeyCertPair;
import org.xipki.security.provider.XiPKIProvider;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.Signer;
import org.xipki.security.sign.UnsignedSigner;
import org.xipki.security.verify.CompositeMLDSAContentVerifierProvider;
import org.xipki.security.verify.KEMContentVerifierProvider;
import org.xipki.security.verify.SignatureContentVerifierProvider;
import org.xipki.security.verify.XDHContentVerifierProvider;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.RandomUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Optional;

/**
 * Key utility class.
 *
 * @author Lijun Liao (xipki)
 */
public class KeyUtil {

  public static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      OIDs.Algo.id_rsaEncryption, DERNull.INSTANCE);

  private static String SM2_PROVIDER_NAME = BridgeKeyUtil.tradProviderName();

  private static String RSAPSSSHAKE_PROVIDER_NAME = BridgeKeyUtil.tradProviderName();

  private KeyUtil() {
  }

  public static void addProviders() {
    String tradProvName = BridgeKeyUtil.tradProviderName();
    boolean alreadyAdded = Security.getProvider(tradProvName) != null;
    if (alreadyAdded) {
      return;
    }

    BridgeKeyUtil.addProviders();
    boolean withSm2 = false;
    try {
      Signature.getInstance(SignAlgo.SM2_SM3.jceName(), tradProvName);
    } catch (NoSuchAlgorithmException e) {
      withSm2 = true;
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("shall not reach here", e);
    }

    boolean withRsaPssShake = false;
    try {
      Signature.getInstance(SignAlgo.RSAPSS_SHAKE128.jceName(), tradProvName);
    } catch (NoSuchAlgorithmException e) {
      withRsaPssShake = true;
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("shall not reach here", e);
    }

    SM2_PROVIDER_NAME = withSm2 ? XiPKIProvider.PROVIDER_NAME : tradProvName;

    RSAPSSSHAKE_PROVIDER_NAME = withRsaPssShake ? XiPKIProvider.PROVIDER_NAME : tradProvName;

    Security.addProvider(new XiPKIProvider(withSm2, withRsaPssShake));
  }

  public static void setSecureRandom(SecureRandom pRandom) {
    BridgeKeyUtil.setSecureRandom(pRandom);
  }

  public static SecureRandom random() {
    return BridgeKeyUtil.random();
  }

  public static byte[] getSM2Z(byte[] userID, byte[] pubPoint) {
    return GMUtil.getSM2Z(userID, pubPoint);
  }

  public static byte[] getSM2Z(byte[] userID, BigInteger pubPointX, BigInteger pubPointY) {
    return GMUtil.getSM2Z(userID, pubPointX, pubPointY);
  }

  public static boolean isSm2primev1Curve(BigInteger curveOrder) {
    return GMUtil.isSm2primev1Curve(curveOrder);
  }

  public static PKCS12KeyStore loadPKCS12KeyStore(InputStream is, char[] password)
      throws XiSecurityException {
    PKCS12KeyStore ks = new PKCS12KeyStore();
    try {
      ks.load(is, password);
    } catch (IOException e) {
      throw new XiSecurityException(e);
    }
    return ks;
  }

  public static KeyStore loadKeyStore(String storeType, InputStream is, char[] password)
      throws XiSecurityException {
    KeyStore keystore;
    try {
      keystore = KeyStore.getInstance(storeType);
    } catch (KeyStoreException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    try {
      keystore.load(is, password);
      return keystore;
    } catch (NoSuchAlgorithmException | ClassCastException
            | CertificateException | IOException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  public static AsymmetricCipherKeyPair generateKeyPair(MLKEMKeyPairGenerator keyPairGenerator)  {
    return BridgeKeyUtil.generateKeyPair(keyPairGenerator);
  }

  public static KeyPair generateKeyPair(KeySpec keySpec, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    switch (keySpec) {
      case RSA2048:
      case RSA3072:
      case RSA4096: {
        KeyPairGenerator kpGen = getKeyPairGenerator("RSA");
        Integer i = keySpec.RSAKeyBitSize();
        assert i != null;
        int keyBitSize = i;
        if (random == null) {
          kpGen.initialize(keyBitSize);
        } else {
          kpGen.initialize(keyBitSize, random);
        }
        return kpGen.generateKeyPair();
      }
      case ED25519:
      case ED448:
      case X25519:
      case X448: {
        String algorithm = keySpec == KeySpec.ED25519 ? "ED25519"
            : keySpec == KeySpec.ED448  ? "ED448"
            : keySpec == KeySpec.X25519 ? "X25519" : "X448";

        int keyBitSize = keySpec == KeySpec.ED25519 ? 256
            : keySpec == KeySpec.ED448  ? 448
            : keySpec == KeySpec.X25519 ? 256 : 448;

        KeyPairGenerator kpGen = getKeyPairGenerator(algorithm);
        if (random == null) {
          kpGen.initialize(keyBitSize);
        } else {
          kpGen.initialize(keyBitSize, random);
        }
        return kpGen.generateKeyPair();
      }
      case MLDSA44:
      case MLDSA65:
      case MLDSA87: {
        MLDSAParameterSpec spec = (keySpec == KeySpec.MLDSA44) ? MLDSAParameterSpec.ml_dsa_44
            : (keySpec == KeySpec.MLDSA65) ? MLDSAParameterSpec.ml_dsa_65
            : MLDSAParameterSpec.ml_dsa_87;

        return BridgeKeyUtil.generateMLDSAKeyPair(spec, random);
      }
      case MLKEM512:
      case MLKEM768:
      case MLKEM1024: {
        MLKEMParameterSpec spec = (keySpec == KeySpec.MLKEM512) ? MLKEMParameterSpec.ml_kem_512
            : keySpec == KeySpec.MLKEM768 ? MLKEMParameterSpec.ml_kem_768
            : MLKEMParameterSpec.ml_kem_1024;

        return BridgeKeyUtil.generateMLKEMKeyPair(spec, random);
      }
      case P256:
      case P384:
      case P521:
      case BRAINPOOLP256R1:
      case BRAINPOOLP384R1:
      case BRAINPOOLP512R1:
      case SM2:
      case FRP256V1: {
        EcCurveEnum curve = keySpec.ecCurve();
        assert curve != null;
        ECGenParameterSpec spec = new ECGenParameterSpec(curve.oid().getId());
        KeyPairGenerator kpGen = getKeyPairGenerator("EC");
        if (random == null) {
          kpGen.initialize(spec);
        } else {
          kpGen.initialize(spec, random);
        }
        return kpGen.generateKeyPair();
      }
    }

    if (keySpec.isCompositeMLDSA()) {
      KeyPair pqcKeyPair = generateKeyPair(keySpec.compositePqcVariant(), random);
      KeyPair tradKeyPair = generateKeyPair(keySpec.compositeTradVariant(), random);
      CompositeMLDSAPrivateKey sk = new CompositeMLDSAPrivateKey(
          (MLDSAPrivateKey) pqcKeyPair.getPrivate(), tradKeyPair.getPrivate());
      CompositeMLDSAPublicKey pk = new CompositeMLDSAPublicKey(
          (MLDSAPublicKey) pqcKeyPair.getPublic(), tradKeyPair.getPublic());
      return new KeyPair(pk, sk);
    } else if (keySpec.isCompositeMLKEM()) {
      KeyPair pqcKeyPair = generateKeyPair(keySpec.compositePqcVariant(), random);
      KeyPair tradKeyPair = generateKeyPair(keySpec.compositeTradVariant(), random);
      CompositeMLKEMPrivateKey sk = new CompositeMLKEMPrivateKey(
          (MLKEMPrivateKey) pqcKeyPair.getPrivate(), tradKeyPair.getPrivate());
      CompositeMLKEMPublicKey pk = new CompositeMLKEMPublicKey(
          (MLKEMPublicKey) pqcKeyPair.getPublic(), tradKeyPair.getPublic());
      return new KeyPair(pk, sk);
    }

    throw new IllegalStateException("unknown keyspec " + keySpec);
  }

  public static KeyPairWithSubjectPublicKeyInfo generateKeyPair2(
      KeySpec keySpec, SecureRandom random) throws Exception {
    KeyPair keypair = generateKeyPair(keySpec, random);
    SubjectPublicKeyInfo pkInfo = KeyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
    return new KeyPairWithSubjectPublicKeyInfo(keypair, pkInfo);
  }

  public static PKCS12KeyStoreWrapper generateKeyPair3(
      KeySpec keySpec, KeystoreGenerationParameters params) throws Exception {
    KeyPairWithSubjectPublicKeyInfo kp = generateKeyPair2(keySpec, params.random());

    // 10 minutes past
    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
    Instant notAfter = notBefore.plus(3650, ChronoUnit.DAYS);

    String dnStr = "CN=DUMMY";
    X500Name subjectDn = new X500Name(dnStr);
    SubjectPublicKeyInfo subjectPublicKeyInfo = kp.subjectPublicKeyInfo();
    Signer signer;
    if (params.unsigned() != null && params.unsigned()) {
      signer = UnsignedSigner.INSTANCE;
    } else {
      signer = getSigner(kp.keypair().getPrivate(),
          kp.keypair().getPublic(), params.random(), true);
    }

    // Generate keystore
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
        subjectDn, BigInteger.ONE, Date.from(notBefore), Date.from(notAfter),
        subjectDn, subjectPublicKeyInfo);

    byte[] encodedSpki = Asn1Util.getPublicKeyData(kp.subjectPublicKeyInfo());
    byte[] skiValue = HashAlgo.SHA1.hash(encodedSpki);
    certGenerator.addExtension(OIDs.Extn.subjectKeyIdentifier, false,
        new SubjectKeyIdentifier(skiValue));
    certGenerator.addExtension(OIDs.Extn.basicConstraints, true,
        new BasicConstraints(false));
    certGenerator.addExtension(OIDs.Extn.keyUsage, true,
        new KeyUsage(KeyUsage.digitalSignature));
    certGenerator.addExtension(OIDs.Extn.extendedKeyUsage, false,
        new ExtendedKeyUsage(new KeyPurposeId[]{
            KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}));

    X509CertificateHolder cert = certGenerator.build(signer.x509Signer());

    PKCS12KeyStore ks = new PKCS12KeyStore();
    ks.load(null, params.password());

    ks.setKeyEntry("main", PrivateKeyInfo.getInstance(kp.keypair().getPrivate().getEncoded()),
        cert.toASN1Structure());

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.password());
    } finally {
      ksStream.flush();
    }

    PKCS12KeyStoreWrapper result = new PKCS12KeyStoreWrapper(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    result.setSubjectPublicKeyInfo(kp.subjectPublicKeyInfo());
    return result;
  } // method generateKeyPair3

  public static KeyStoreWrapper generateSecretKey(
      String algorithm, int keyBitLen, KeystoreGenerationParameters params) throws Exception {
    if (keyBitLen % 8 != 0) {
      throw new IllegalArgumentException("keyBitLen (" + keyBitLen + ") must be multiple of 8");
    }

    SecureRandom random = params.random();
    byte[] keyValue;
    if (random == null) {
      keyValue = RandomUtil.nextBytes(keyBitLen / 8);
    } else {
      keyValue = new byte[keyBitLen / 8];
      random.nextBytes(keyValue);
    }

    SecretKey secretKey = new SecretKeySpec(keyValue, algorithm);

    KeyStore ks = KeyUtil.loadKeyStore("JCEKS", null, params.password());
    ks.setKeyEntry("main", secretKey, params.password(), null);
    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.password());
    } finally {
      ksStream.flush();
    }

    KeyStoreWrapper result = new KeyStoreWrapper(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    return result;
  }

  private static KeyPairGenerator getKeyPairGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    String upperAlg = algorithm.toUpperCase(Locale.ROOT);
    if ("ECDSA".equals(upperAlg)) {
      algorithm = "EC";
    }

    String provider = providerName(upperAlg);
    return KeyPairGenerator.getInstance(algorithm, provider);
  } // method getKeyPairGenerator

  public static PrivateKey getPrivateKey(PrivateKeyInfo skInfo) throws InvalidKeySpecException {
    return CompositeKeyInfoConverter.supportsPrivateKey(skInfo.getPrivateKeyAlgorithm())
        ? CompositeKeyInfoConverter.generatePrivate(skInfo) : BridgeKeyUtil.getPrivateKey(skInfo);
  }

  public static PublicKey getPublicKey(SubjectPublicKeyInfo pkInfo) throws InvalidKeySpecException {
    return CompositeKeyInfoConverter.supportsPublicKey(pkInfo.getAlgorithm())
        ? CompositeKeyInfoConverter.generatePublic(pkInfo) : BridgeKeyUtil.getPublicKey(pkInfo);
  }

  public static RSAPublicKey getRSAPublicKey(RSAPublicKeySpec keySpec)
      throws InvalidKeySpecException {
    Args.notNull(keySpec, "keySpec");
    try {
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidKeySpecException("could not find KeyFactory for RSA: " + ex.getMessage());
    }
  }

  public static void initSign(Signature sig, PrivateKey key, SecureRandom rnd)
      throws InvalidKeyException {
    BridgeKeyUtil.initSign(sig, key, rnd);
  }

  public static void initVerify(Signature sig, PublicKey key) throws InvalidKeyException {
    BridgeKeyUtil.initVerify(sig, key);
  }

  public static void setContext(Signature sig, byte[] context)
      throws InvalidAlgorithmParameterException {
    BridgeKeyUtil.setContext(sig, context);
  }

  public static byte[] mgfShake(HashAlgo mgfDigest, byte[] Z, int length) {
    return BridgeKeyUtil.mgfShake(mgfDigest.jceName(), Z, length);
  }

  public static MLDSAPublicKey wrapMLDSAPublicKey(PublicKey key) {
    return BridgeKeyUtil.wrapMLDSAPublicKey(key);
  }

  public static MLDSAPrivateKey wrapMLDSAPrivateKey(PrivateKey key) {
    return BridgeKeyUtil.wrapMLDSAPrivateKey(key);
  }

  public static MLKEMPublicKey wrapMLKEMPublicKey(PublicKey key) {
    return BridgeKeyUtil.wrapMLKEMPublicKey(key);
  }

  public static MLKEMPrivateKey wrapMLKEMPrivateKey(PrivateKey key) {
    return BridgeKeyUtil.wrapMLKEMPrivateKey(key);
  }

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
      throws InvalidKeyException {
    Args.notNull(publicKey, "publicKey");

    if (publicKey instanceof RSAPublicKey) {
      RSAPublicKey rsaPubKey = (RSAPublicKey) publicKey;
      try {
        return new SubjectPublicKeyInfo(ALGID_RSA,
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(rsaPubKey.getModulus(),
                rsaPubKey.getPublicExponent()));
      } catch (IOException ex) {
        throw new InvalidKeyException(ex.getMessage(), ex);
      }
    } else if (publicKey instanceof ECPublicKey) {
      ECPublicKey ecPubKey = (ECPublicKey) publicKey;

      ECParameterSpec paramSpec = ecPubKey.getParams();
      ASN1ObjectIdentifier curveOid = detectCurveOid(paramSpec);

      java.security.spec.ECPoint pointW = ecPubKey.getW();
      BigInteger wx = pointW.getAffineX();
      if (wx.signum() != 1) {
        throw new InvalidKeyException("Wx is not positive");
      }

      BigInteger wy = pointW.getAffineY();
      if (wy.signum() != 1) {
        throw new InvalidKeyException("Wy is not positive");
      }

      int keysize = (paramSpec.getCurve().getField().getFieldSize() + 7) / 8;
      byte[] wxBytes = BigIntegers.asUnsignedByteArray(keysize, wx);
      byte[] wyBytes = BigIntegers.asUnsignedByteArray(keysize, wy);
      byte[] pubKey = IoUtil.concatenate(new byte[]{4}, wxBytes, wyBytes);
      AlgorithmIdentifier algId = new AlgorithmIdentifier(OIDs.Algo.id_ecPublicKey, curveOid);
      return new SubjectPublicKeyInfo(algId, pubKey);
    } else {
      return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    }
  } // method createSubjectPublicKeyInfo

  public static ECPublicKey createECPublicKey(EcCurveEnum curve, byte[] encodedPoint)
      throws InvalidKeySpecException {
    return (ECPublicKey) getPublicKey(new SubjectPublicKeyInfo(curve.algId(), encodedPoint));
  }

  public static PrivateKeyInfo buildPrivateKeyInfo(ASN1ObjectIdentifier oid, byte[] encodedSk) {
    return buildPrivateKeyInfo(new AlgorithmIdentifier(oid), encodedSk);
  }

  /**
   * <pre>
   * OneAsymmetricKey ::= SEQUENCE {
   *   version                   Version,
   *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
   *   privateKey                PrivateKey,
   *   attributes            [0] Attributes OPTIONAL,
   *   ...,
   *   [[2: publicKey        [1] PublicKey OPTIONAL ]],
   *   ...
   * }
   * </pre>
   */
  public static PrivateKeyInfo buildPrivateKeyInfo(AlgorithmIdentifier algId, byte[] encodedSk) {
    ASN1EncodableVector vec = new ASN1EncodableVector(3);
    vec.add(new ASN1Integer(0));
    vec.add(algId);
    vec.add(new DEROctetString(encodedSk));
    return PrivateKeyInfo.getInstance(new DERSequence(vec));
  }

  public static ASN1ObjectIdentifier detectCurveOid(ECParameterSpec paramSpec) {
    byte[] ecParams = Optional.ofNullable(
        Functions.getEcParams(paramSpec.getOrder(), paramSpec.getGenerator().getAffineX()))
        .orElseThrow(() -> new IllegalArgumentException("unknown paramSpec"));

    return new ASN1ObjectIdentifier(org.xipki.util.codec.asn1.Asn1Util.decodeOid(ecParams));
  }

  public static ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
      throws InvalidKeyException {
    return getContentVerifierProvider(publicKey, null, null);
  }

  public static ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert, SecretKey ownerMasterKey)
      throws InvalidKeyException {
    String keyAlg = Args.notNull(publicKey, "publicKey").getAlgorithm().toUpperCase();

    keyAlg = keyAlg.replace("-", "");
    switch (keyAlg) {
      case "X25519":
      case "X448":
        if (ownerKeyAndCert == null) {
          throw new InvalidKeyException("ownerKeyAndCert is required but absent");
        }
        return new XDHContentVerifierProvider(publicKey, ownerKeyAndCert);
      case "MLKEM512":
      case "MLKEM768":
      case "MLKEM1024":
        if (ownerMasterKey == null) {
          throw new InvalidKeyException("ownerMasterKey is required but absent");
        }
        return new KEMContentVerifierProvider(publicKey, ownerMasterKey);
    }

    KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(
        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm());
    if (keySpec != null) {
      if (keySpec.isCompositeMLKEM()) {
        if (ownerMasterKey == null) {
          throw new InvalidKeyException("ownerMasterKey is required but absent");
        }
        return new KEMContentVerifierProvider(publicKey, ownerMasterKey);
      } else if (keySpec.isCompositeMLDSA() && publicKey instanceof CompositeMLDSAPublicKey) {
        return new CompositeMLDSAContentVerifierProvider((CompositeMLDSAPublicKey) publicKey);
      }
    }

    return new SignatureContentVerifierProvider(publicKey);
  } // method getContentVerifierProvider

  public static Signer getSigner(PrivateKey key, PublicKey publicKey, SecureRandom random)
      throws Exception {
    return getSigner(key, publicKey, random, false);
  }

  public static Signer getSigner(
      PrivateKey key, PublicKey publicKey, SecureRandom random, boolean allowUnsigned)
      throws Exception {
    SignAlgo algo;
    if (key instanceof RSAPrivateKey) {
      algo = SignAlgo.RSAPSS_SHA256;
    } else if (key instanceof ECPrivateKey) {
      BigInteger order = ((ECPrivateKey) key).getParams().getOrder();
      if (KeyUtil.isSm2primev1Curve(order)) {
        algo = SignAlgo.SM2_SM3;
      } else {
        int orderBitLength = order.bitLength();
        algo = orderBitLength > 384 ? SignAlgo.ECDSA_SHA512
            :  orderBitLength > 256 ? SignAlgo.ECDSA_SHA384
            :  orderBitLength > 160 ? SignAlgo.ECDSA_SHA256 :  SignAlgo.ECDSA_SHA1;
      }
    } else if (key instanceof MLDSAPrivateKey) {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      algo = SignAlgo.getInstance(spki.getAlgorithm());
    } else {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      KeySpec keySpec = KeySpec.ofPublicKey(spki);
      if (keySpec == null) {
        throw new IllegalArgumentException("unknown public key algorithm "
            + spki.getAlgorithm().getAlgorithm());
      }

      if (keySpec.isEdwardsEC()) {
        algo = (keySpec == KeySpec.ED25519) ? SignAlgo.ED25519 : SignAlgo.ED448;
      } else if (keySpec == KeySpec.MLDSA44) {
        algo = SignAlgo.MLDSA44;
      } else if (keySpec == KeySpec.MLDSA65) {
        algo = SignAlgo.MLDSA65;
      } else if (keySpec == KeySpec.MLDSA87) {
        algo = SignAlgo.MLDSA87;
      } else if (keySpec.isCompositeMLDSA()) {
        algo = SignAlgo.getInstance(keySpec.algorithmIdentifier());
      } else if (allowUnsigned & (keySpec.isMontgomeryEC() ||
          keySpec.isMlkem() || keySpec.isCompositeMLKEM())) {
        return UnsignedSigner.INSTANCE;
      } else {
        throw new IllegalArgumentException("unknown key-spec " + keySpec);
      }
    }

    P12ContentSignerBuilder builder = new P12ContentSignerBuilder(key, publicKey);
    ConcurrentSigner csigner = builder.createSigner(algo, 1, random);
    return csigner.borrowSigner();
  } // method getContentSigner

  public static SubjectPublicKeyInfo getPublicKeyOfFirstKeyEntry(
      String keystoreType, String keystorePath, char[] keystorePassword)
      throws XiSecurityException {
    try (InputStream is = new FileInputStream(IoUtil.expandFilepath(keystorePath))) {
      KeyStore p12 = loadKeyStore(keystoreType, is, keystorePassword);

      Enumeration<String> aliases = p12.aliases();
      String keyAlias = null;
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (p12.isKeyEntry(alias)) {
          keyAlias = alias;
          break;
        }
      }

      Certificate cert = Certificate.getInstance(p12.getCertificate(keyAlias).getEncoded());
      return cert.getSubjectPublicKeyInfo();
    } catch (Exception e) {
      throw new XiSecurityException(e);
    }
  }

  public static byte[] hkdf(HashAlgo hashAlgo, byte[] salt, byte[] ikm, byte[] info, int outSize) {
    // TODO: check the correctness
    // Step 1: Extract: HKDF-Extract(salt, IKM) -> PRK
    String hmacAlgName = "HMAC-" + hashAlgo.jceName();

    Mac mac;
    try {
      mac = Mac.getInstance(hmacAlgName);
      mac.init(new SecretKeySpec(salt, hmacAlgName));
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new IllegalStateException(ex);
    }

    SecretKeySpec prk = new SecretKeySpec(mac.doFinal(ikm), hmacAlgName);

    int hmacSize = hashAlgo.length();
    // Step 2: Expand: HKDF-Expand(PRK, info, L) -> OKM

    int num = (outSize + hmacSize - 1) / hmacSize;
    if (num > 254) {
      throw new IllegalArgumentException("outSize too big: " + outSize);
    }

    byte[] okm = new byte[outSize];

    int off = 0;
    byte[] ti_1 = new byte[0];

    for (int i = 0; i < num; i++) {
      try {
        mac.init(prk);
      } catch (InvalidKeyException e) {
        throw new RuntimeException(e);
      }

      mac.update(ti_1);
      mac.update(info);
      mac.update((byte) i);
      byte[] t_i = mac.doFinal();
      System.arraycopy(t_i, 0, okm, off, Math.min(outSize - off, hmacSize));
      ti_1 = t_i;
    }
    return okm;
  }

  public static byte[] p12CalculatePbeMac(
        AlgorithmIdentifier macAlgorithm, byte[] salt, int itCount,
        char[] password, boolean wrongPkcs12Zero, byte[] data) throws Exception {
    return BridgeKeyUtil.p12CalculatePbeMac(macAlgorithm, salt, itCount,
        password, wrongPkcs12Zero, data);
  }

  public static String tradProviderName() {
    return BridgeKeyUtil.tradProviderName();
  }

  public static String pqcProviderName() {
    return BridgeKeyUtil.pqcProviderName();
  }

  public static String providerName(String algo) {
    algo = algo.replace("_", "").replace("-", "");
    if (StringUtil.orEqualsIgnoreCase(algo,
        "SM2", "SM3", "SM2WITHSM3", "SM3WITHSM2") ||
        algo.contains(OIDs.Algo.sm2sign_with_sm3.getId()) ||
        algo.contains(OIDs.Algo.id_sm3.getId())) {
      return SM2_PROVIDER_NAME;
    } else if (StringUtil.orEqualsIgnoreCase(algo, "RSAPSSIWTHSHAKE128",
        "RSAPSSIWTHSHAKE256", "SHAKE128WITHRSAPSS", "SHAKE256WITHRSAPSS")) {
      return RSAPSSSHAKE_PROVIDER_NAME;
    } else {
      return BridgeKeyUtil.providerName(algo);
    }
  }

  public static byte[] crmfDecryptEncryptedKey(
      CertifiedKeyPair certifiedKeyPair, CmpCallback callback) throws GeneralSecurityException {
    return BridgeKeyUtil.crmfDecryptEncryptedKey(certifiedKeyPair, callback);
  }

  public static byte[] decapsulateKey(
      KeySpec keySpec, byte[] privateKeyValue, byte[] encapsulatedKey) {
    BridgeMlkemVariant variant = KEMUtil.toBridgeMlkemVariant(keySpec);
    return BridgeKeyUtil.decapsulateKey(variant, privateKeyValue, encapsulatedKey);
  }

  public static KeyPairBytes generateMlkemKeyPair(KeySpec keySpec, SecureRandom rnd) {
    BridgeMlkemVariant variant = KEMUtil.toBridgeMlkemVariant(keySpec);
    BridgeKeyPairBytes bytesPair = BridgeKeyUtil.generateMlkemKeyPair(variant, rnd);
    return new KeyPairBytes(bytesPair.privateKey(), bytesPair.publicKey());
  }

}
