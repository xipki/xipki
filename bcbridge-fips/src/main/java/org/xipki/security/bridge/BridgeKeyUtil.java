// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.PBKD;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.pqc.crypto.Xof;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.ContextParameterSpec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import java.util.Set;

/**
 * Bridge Key Util.
 *
 * @author Lijun Liao (xipki)
 */
public class BridgeKeyUtil {

  public static final String id_ml_dsa_44 = "2.16.840.1.101.3.4.3.17";

  public static final String id_ml_dsa_65 = "2.16.840.1.101.3.4.3.18";

  public static final String id_ml_dsa_87 = "2.16.840.1.101.3.4.3.19";

  public static final String id_ml_kem_512 = "2.16.840.1.101.3.4.4.1";

  public static final String id_ml_kem_768 = "2.16.840.1.101.3.4.4.2";

  public static final String id_ml_kem_1024 = "2.16.840.1.101.3.4.4.3";

  // composite_sigs
  private static final String id_MLDSA44_RSA2048_PSS_SHA256 = "1.3.6.1.5.5.7.6.37";

  private static final String id_MLDSA44_RSA2048_PKCS15_SHA256 = "1.3.6.1.5.5.7.6.38";

  private static final String id_MLDSA44_Ed25519_SHA512 = "1.3.6.1.5.5.7.6.39";

  private static final String id_MLDSA44_ECDSA_P256_SHA256 = "1.3.6.1.5.5.7.6.40";

  private static final String id_MLDSA65_RSA3072_PSS_SHA512 = "1.3.6.1.5.5.7.6.41";

  private static final String id_MLDSA65_RSA3072_PKCS15_SHA512 = "1.3.6.1.5.5.7.6.42";

  private static final String id_MLDSA65_RSA4096_PSS_SHA512 = "1.3.6.1.5.5.7.6.43";

  private static final String id_MLDSA65_RSA4096_PKCS15_SHA512 = "1.3.6.1.5.5.7.6.44";

  private static final String id_MLDSA65_ECDSA_P256_SHA512 = "1.3.6.1.5.5.7.6.45";

  private static final String id_MLDSA65_ECDSA_P384_SHA512 = "1.3.6.1.5.5.7.6.46";

  private static final String id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = "1.3.6.1.5.5.7.6.47";

  private static final String id_MLDSA65_Ed25519_SHA512 = "1.3.6.1.5.5.7.6.48";

  private static final String id_MLDSA87_ECDSA_P384_SHA512 = "1.3.6.1.5.5.7.6.49";

  private static final String id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = "1.3.6.1.5.5.7.6.50";

  private static final String id_MLDSA87_Ed448_SHAKE256 = "1.3.6.1.5.5.7.6.51";

  private static final String id_MLDSA87_RSA3072_PSS_SHA512 = "1.3.6.1.5.5.7.6.52";

  private static final String id_MLDSA87_RSA4096_PSS_SHA512 = "1.3.6.1.5.5.7.6.53";

  private static final String id_MLDSA87_ECDSA_P521_SHA512 = "1.3.6.1.5.5.7.6.54";

  // composite_kem
  private static final String id_MLKEM768_RSA2048_SHA3_256 = "1.3.6.1.5.5.7.6.55";

  private static final String id_MLKEM768_RSA3072_SHA3_256 = "1.3.6.1.5.5.7.6.56";

  private static final String id_MLKEM768_RSA4096_SHA3_256 = "1.3.6.1.5.5.7.6.57";

  private static final String id_MLKEM768_X25519_SHA3_256 = "1.3.6.1.5.5.7.6.58";

  private static final String id_MLKEM768_ECDH_P256_SHA3_256 = "1.3.6.1.5.5.7.6.59";

  private static final String id_MLKEM768_ECDH_P384_SHA3_256 = "1.3.6.1.5.5.7.6.60";

  private static final String id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256 = "1.3.6.1.5.5.7.6.61";

  private static final String id_MLKEM1024_RSA3072_SHA3_256 = "1.3.6.1.5.5.7.6.62";

  private static final String id_MLKEM1024_ECDH_P384_SHA3_256 = "1.3.6.1.5.5.7.6.63";

  private static final String id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256 = "1.3.6.1.5.5.7.6.64";

  private static final String id_MLKEM1024_X448_SHA3_256 = "1.3.6.1.5.5.7.6.65";

  private static final String id_MLKEM1024_ECDH_P521_SHA3_256 = "1.3.6.1.5.5.7.6.66";

  private static final Set<String> MLDSAOids = Set.of(id_ml_dsa_44, id_ml_dsa_65, id_ml_dsa_87);

  private static final Set<String> MLKEMOids = Set.of(id_ml_kem_512, id_ml_kem_768, id_ml_kem_1024);

  private static SecureRandom random = new SecureRandom();

  private static final Set<String> compositeMLDSAOids = Set.of(
      id_MLDSA44_RSA2048_PSS_SHA256,
      id_MLDSA44_RSA2048_PKCS15_SHA256,
      id_MLDSA44_Ed25519_SHA512,
      id_MLDSA44_ECDSA_P256_SHA256,
      id_MLDSA65_RSA3072_PSS_SHA512,
      id_MLDSA65_RSA3072_PKCS15_SHA512,
      id_MLDSA65_RSA4096_PSS_SHA512,
      id_MLDSA65_RSA4096_PKCS15_SHA512,
      id_MLDSA65_ECDSA_P256_SHA512,
      id_MLDSA65_ECDSA_P384_SHA512,
      id_MLDSA65_ECDSA_brainpoolP256r1_SHA512,
      id_MLDSA65_Ed25519_SHA512,
      id_MLDSA87_ECDSA_P384_SHA512,
      id_MLDSA87_ECDSA_brainpoolP384r1_SHA512,
      id_MLDSA87_Ed448_SHAKE256,
      id_MLDSA87_RSA3072_PSS_SHA512,
      id_MLDSA87_RSA4096_PSS_SHA512,
      id_MLDSA87_ECDSA_P521_SHA512);

  private static final Set<String> compositeMLKEMOids = Set.of(
      id_MLKEM768_RSA2048_SHA3_256,
      id_MLKEM768_RSA3072_SHA3_256,
      id_MLKEM768_RSA4096_SHA3_256,
      id_MLKEM768_X25519_SHA3_256,
      id_MLKEM768_ECDH_P256_SHA3_256,
      id_MLKEM768_ECDH_P384_SHA3_256,
      id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256,
      id_MLKEM1024_RSA3072_SHA3_256,
      id_MLKEM1024_ECDH_P384_SHA3_256,
      id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256,
      id_MLKEM1024_X448_SHA3_256,
      id_MLKEM1024_ECDH_P521_SHA3_256);

  private static final Object lock = new Object();

  private static BouncyCastleFipsProvider bcProv;

  private static BouncyCastlePQCProvider pqcProv;

  public static String tradProviderName() {
    return BouncyCastleFipsProvider.PROVIDER_NAME;
  }

  public static String pqcProviderName() {
    return BouncyCastlePQCProvider.PROVIDER_NAME;
  }

  public static String providerName(String algo) {
    String calgo = algo.toUpperCase().replace("-", "").replace("_", "");
    if (isPqcOid(calgo)) {
      return pqcProviderName();
    } else if (calgo.contains("MLDSA") || calgo.contains("MLKEM") ||
        calgo.contains("SLHDSA")) {
      return pqcProviderName();
    } else {
      return tradProviderName();
    }
  }

  public static void addProviders() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      synchronized (lock) {
        if (bcProv == null) {
          bcProv = new BouncyCastleFipsProvider();
        }
        Security.addProvider(bcProv);
      }
    }

    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
      synchronized (lock) {
        if (pqcProv == null) {
          pqcProv = new BouncyCastlePQCProvider();
          CryptoServicesRegistrar.setSecureRandom(random);
        }
        Security.addProvider(pqcProv);
      }
    }
  }

  public static void setSecureRandom(SecureRandom pRandom) {
    random = Objects.requireNonNull(pRandom, "random shall not be null");
  }

  public static SecureRandom random() {
    return random;
  }

  private static boolean isPqcOid(String oid) {
    return MLDSAOids.contains(oid) || MLKEMOids.contains(oid) ||
        compositeMLDSAOids.contains(oid) || compositeMLKEMOids.contains(oid);
  }

  public static PrivateKey getPrivateKey(PrivateKeyInfo skInfo)
      throws InvalidKeySpecException {
    String oid = skInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
    try {
      if (isPqcOid(oid)) {
        return BouncyCastlePQCProvider.getPrivateKey(skInfo);
      } else {
        KeyFactory kf = getTradKeyFactory(oid);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(skInfo.getEncoded()));
      }
    } catch (IOException | NoSuchAlgorithmException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
  }

  public static PublicKey getPublicKey(SubjectPublicKeyInfo pkInfo)
      throws InvalidKeySpecException {
    String oid = pkInfo.getAlgorithm().getAlgorithm().getId();
    try {
      if (isPqcOid(oid)) {
        return BouncyCastlePQCProvider.getPublicKey(pkInfo);
      } else {
        KeyFactory kf = getTradKeyFactory(oid);
        return kf.generatePublic(new X509EncodedKeySpec(pkInfo.getEncoded()));
      }
    } catch (IOException | NoSuchAlgorithmException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
  }

  private static KeyFactory getTradKeyFactory(String name) throws NoSuchAlgorithmException {
    KeyFactory kf;
    try {
      kf = KeyFactory.getInstance(name, tradProviderName());
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      kf = KeyFactory.getInstance(name);
    }
    return kf;
  }

  public static void initSign(Signature sig, PrivateKey key, SecureRandom rnd)
      throws InvalidKeyException {
    if (key instanceof MLDSAPrivateKey) {
      key = ((MLDSAPrivateKey) key).getBc();
    }

    if (rnd != null) {
      sig.initSign(key, rnd);
    } else {
      sig.initSign(key);
    }
  }

  public static void initVerify(Signature sig, PublicKey key) throws InvalidKeyException {
    if (key instanceof MLDSAPublicKey) {
      key = ((MLDSAPublicKey) key).getBc();
    }

    sig.initVerify(key);
  }

  public static void setContext(Signature sig, byte[] context)
      throws InvalidAlgorithmParameterException {
    if (context != null && context.length > 0) {
      sig.setParameter(new ContextParameterSpec(context));
    }
  }

  public static byte[] mgfShake(String mgfHashAlgo, byte[] Z, int length) {
    int shakeBitLen;

    if (    "SHAKE128".equalsIgnoreCase(mgfHashAlgo) ||
        "SHAKE128-256".equalsIgnoreCase(mgfHashAlgo)) {
      shakeBitLen = 128;
    } else if ( "SHAKE256".equalsIgnoreCase(mgfHashAlgo) ||
            "SHAKE256-512".equalsIgnoreCase(mgfHashAlgo)) {
      shakeBitLen = 256;
    } else {
      throw new IllegalArgumentException("invalid mgfHashAlgo " + mgfHashAlgo);
    }

    Xof xof = InternalUtil.newSHAKE(shakeBitLen);
    xof.update(Z, 0, Z.length);
    byte[] res = new byte[length];
    xof.doFinal(res, 0, length);
    return res;
  }

  public static MLDSAPublicKey wrapMLDSAPublicKey(PublicKey key) {
    return new MLDSAPublicKey((org.bouncycastle.pqc.jcajce.interfaces.MLDSAPublicKey) key);
  }

  public static MLDSAPrivateKey wrapMLDSAPrivateKey(PrivateKey key) {
    return new MLDSAPrivateKey((org.bouncycastle.pqc.jcajce.interfaces.MLDSAPrivateKey) key);
  }

  public static MLKEMPublicKey wrapMLKEMPublicKey(PublicKey key) {
    return new MLKEMPublicKey((org.bouncycastle.pqc.jcajce.interfaces.MLKEMPublicKey) key);
  }

  public static MLKEMPrivateKey wrapMLKEMPrivateKey(PrivateKey key) {
    return new MLKEMPrivateKey((org.bouncycastle.pqc.jcajce.interfaces.MLKEMPrivateKey) key);
  }

  public static KeyPair generateMLDSAKeyPair(MLDSAParameterSpec spec, SecureRandom random)
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-DSA");
    if (random == null) {
      kpGen.initialize(spec.getBc());
    } else {
      kpGen.initialize(spec.getBc(), random);
    }

    KeyPair kp = kpGen.generateKeyPair();

    return new KeyPair(
        new MLDSAPublicKey((org.bouncycastle.pqc.jcajce.interfaces.MLDSAPublicKey) kp.getPublic()),
        new MLDSAPrivateKey(
            (org.bouncycastle.pqc.jcajce.interfaces.MLDSAPrivateKey) kp.getPrivate()));
  }

  public static KeyPair generateMLKEMKeyPair(MLKEMParameterSpec spec, SecureRandom random)
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-KEM");
    if (random == null) {
      kpGen.initialize(spec.getBc());
    } else {
      kpGen.initialize(spec.getBc(), random);
    }

    KeyPair kp = kpGen.generateKeyPair();

    return new KeyPair(
        new MLKEMPublicKey((org.bouncycastle.pqc.jcajce.interfaces.MLKEMPublicKey) kp.getPublic()),
        new MLKEMPrivateKey(
            (org.bouncycastle.pqc.jcajce.interfaces.MLKEMPrivateKey) kp.getPrivate()));
  }

  public static AsymmetricCipherKeyPair generateKeyPair(MLKEMKeyPairGenerator keyPairGenerator)  {
    return new AsymmetricCipherKeyPair(keyPairGenerator.generateKeyPair());
  }

  public static byte[] p12CalculatePbeMac(
        AlgorithmIdentifier macAlgorithm, byte[] salt, int itCount,
        char[] password, boolean wrongPkcs12Zero, byte[] data)
      throws Exception {
    if (wrongPkcs12Zero && (password == null ||password.length == 0)) {
      return doCalculatePbeMac(macAlgorithm, salt, itCount, new byte[2], data);
    }

    return doCalculatePbeMac(macAlgorithm, salt, itCount,
            PasswordConverter.PKCS12.convert(password), data);
  }

  private static byte[] doCalculatePbeMac(
      AlgorithmIdentifier algID, byte[] salt, int itCount, byte[] passwordBytes, byte[] data)
      throws Exception {
    byte[] derivedKey = getDerivedMacKey(algID, passwordBytes, salt, itCount);

    String algOID = algID.getAlgorithm().getId();
    Mac mac = Mac.getInstance(algOID, tradProviderName());

    mac.init(new SecretKeySpec(derivedKey, algOID));
    mac.update(data);

    return mac.doFinal();
  }

  private static byte[] getDerivedMacKey(
      AlgorithmIdentifier algID, byte[] password, byte[] salt, int itCount) {
    PasswordBasedDeriver<?> deriver;
    int keySize;
    if (algID.getAlgorithm().equals(CryptoProObjectIdentifiers.gostR3411)) {
      deriver = new PBKD.DeriverFactory().createDeriver(
          PBKD.PKCS12.using(SecureHash.Algorithm.GOST3411, password)
              .withSalt(salt).withIterationCount(itCount));
      keySize = 32;
    } else if (algID.getAlgorithm().equals(NISTObjectIdentifiers.id_sha224)) {
      deriver = new PBKD.DeriverFactory().createDeriver(
          PBKD.PKCS12.using(FipsSHS.Algorithm.SHA224, password)
              .withSalt(salt).withIterationCount(itCount));
      keySize = 28;
    } else if (algID.getAlgorithm().equals(NISTObjectIdentifiers.id_sha256)) {
      deriver = new PBKD.DeriverFactory().createDeriver(
          PBKD.PKCS12.using(FipsSHS.Algorithm.SHA256, password)
              .withSalt(salt).withIterationCount(itCount));
      keySize = 32;
    } else {
      deriver = new PBKD.DeriverFactory().createDeriver(
          PBKD.PKCS12.using(FipsSHS.Algorithm.SHA1, password)
              .withSalt(salt).withIterationCount(itCount));
      keySize = 20;
    }

    return deriver.deriveKey(PasswordBasedDeriver.KeyType.MAC, keySize);
  }

  public static BridgeKeyPairBytes generateMlkemKeyPair(
      BridgeMlkemVariant variant, SecureRandom rnd) {
    Objects.requireNonNull(variant, "variant shall not be null");
    MLKEMKeyPairGenerator kpGen = new MLKEMKeyPairGenerator();
    MLKEMParameters mlkemParams =
          variant == BridgeMlkemVariant.mlkem512 ? MLKEMParameters.ml_kem_512
        : variant == BridgeMlkemVariant.mlkem768 ? MLKEMParameters.ml_kem_768
        : MLKEMParameters.ml_kem_1024;
    MLKEMKeyGenerationParameters params = new MLKEMKeyGenerationParameters(rnd, mlkemParams);
    kpGen.init(params);
    AsymmetricCipherKeyPair keyPair = BridgeKeyUtil.generateKeyPair(kpGen);
    return new BridgeKeyPairBytes(
        ((MLKEMPrivateKeyParameters) keyPair.getPrivate()).getEncoded(),
        ((MLKEMPublicKeyParameters) keyPair.getPublic()).getEncoded());
  }

  public static byte[] decapsulateKey(
      BridgeMlkemVariant variant, byte[] privateKeyValue, byte[] encapsulatedKey) {
    MLKEMParameters params =
        (variant == BridgeMlkemVariant.mlkem512) ? MLKEMParameters.ml_kem_512
        : (variant == BridgeMlkemVariant.mlkem768) ? MLKEMParameters.ml_kem_768
        : MLKEMParameters.ml_kem_1024;

    MLKEMPrivateKeyParameters priParams = new MLKEMPrivateKeyParameters(params, privateKeyValue);
    MLKEMExtractor gen = new MLKEMExtractor(priParams);
    return gen.extractSecret(encapsulatedKey);
  }

  public static byte[] crmfDecryptEncryptedKey(
      CertifiedKeyPair certifiedKeyPair, CmpCallback callback)
      throws GeneralSecurityException {
    return (certifiedKeyPair.getPrivateKey() == null) ? null
        : callback.decrypt(certifiedKeyPair.getPrivateKey());
  }

}
