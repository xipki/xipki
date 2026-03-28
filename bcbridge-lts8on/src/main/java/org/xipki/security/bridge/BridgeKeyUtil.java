// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

import javax.crypto.Mac;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

/**
 * Bridge Key Util.
 *
 * @author Lijun Liao (xipki)
 */
public class BridgeKeyUtil {

  private static final Object lock = new Object();

  private static BouncyCastleProvider bcProv;

  private static final JcaJceHelper helper = new BCJcaJceHelper();

  private static SecureRandom random = new SecureRandom();

  public static String tradProviderName() {
    return BouncyCastleProvider.PROVIDER_NAME;
  }

  public static String pqcProviderName() {
    return BouncyCastleProvider.PROVIDER_NAME;
  }

  public static String providerName(String algo) {
    return BouncyCastleProvider.PROVIDER_NAME;
  }

  public static void addProviders() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      synchronized (lock) {
        if (bcProv == null) {
          bcProv = new BouncyCastleProvider();
        }
        Security.addProvider(bcProv);
      }
    }
  }

  public static void setSecureRandom(SecureRandom pRandom) {
    random = Objects.requireNonNull(pRandom, "random shall not be null");
  }

  public static SecureRandom random() {
    return random;
  }

  public static PrivateKey getPrivateKey(PrivateKeyInfo pkInfo) throws InvalidKeySpecException {
    try {
      return BouncyCastleProvider.getPrivateKey(pkInfo);
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
  }

  public static PublicKey getPublicKey(SubjectPublicKeyInfo pkInfo) throws InvalidKeySpecException {
    try {
      return BouncyCastleProvider.getPublicKey(pkInfo);
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
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
    Xof xof;
    if (    "SHAKE128".equalsIgnoreCase(mgfHashAlgo) ||
        "SHAKE128-256".equalsIgnoreCase(mgfHashAlgo)) {
      xof = new SHAKEDigest(128);
    } else if ("SHAKE256".equalsIgnoreCase(mgfHashAlgo) ||
          "SHAKE256-512".equalsIgnoreCase(mgfHashAlgo)) {
      xof = new SHAKEDigest(256);
    } else {
      throw new IllegalArgumentException("invalid mgfHashAlgo " + mgfHashAlgo);
    }

    xof.update(Z, 0, Z.length);
    byte[] res = new byte[length];
    xof.doFinal(res, 0, length);
    return res;
  }

  public static MLDSAPublicKey wrapMLDSAPublicKey(PublicKey key) {
    return new MLDSAPublicKey((org.bouncycastle.jcajce.interfaces.MLDSAPublicKey) key);
  }

  public static MLDSAPrivateKey wrapMLDSAPrivateKey(PrivateKey key) {
    return new MLDSAPrivateKey((org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) key);
  }

  public static MLKEMPublicKey wrapMLKEMPublicKey(PublicKey key) {
    return new MLKEMPublicKey((org.bouncycastle.jcajce.interfaces.MLKEMPublicKey) key);
  }

  public static MLKEMPrivateKey wrapMLKEMPrivateKey(PrivateKey key) {
    return new MLKEMPrivateKey((org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey) key);
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
        new MLDSAPublicKey((org.bouncycastle.jcajce.interfaces.MLDSAPublicKey) kp.getPublic()),
        new MLDSAPrivateKey((org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) kp.getPrivate()));
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
        new MLKEMPublicKey((org.bouncycastle.jcajce.interfaces.MLKEMPublicKey) kp.getPublic()),
        new MLKEMPrivateKey((org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey) kp.getPrivate()));
  }

  public static AsymmetricCipherKeyPair generateKeyPair(MLKEMKeyPairGenerator keyPairGenerator)  {
    return new AsymmetricCipherKeyPair(keyPairGenerator.generateKeyPair());
  }

  public static byte[] p12CalculatePbeMac(
      AlgorithmIdentifier macAlgorithm, byte[] salt, int itCount,
      char[] password, boolean wrongPkcs12Zero, byte[] data)
      throws Exception {
    ASN1ObjectIdentifier oid = macAlgorithm.getAlgorithm();
    // id_PBMAC1: "1.2.840.113549.1.5.14"
    if ("1.2.840.113549.1.5.14".equals(oid.getId())) {
      PBMAC1Params pbmac1Params = PBMAC1Params.getInstance(macAlgorithm.getParameters());
      if (pbmac1Params == null) {
        throw new IOException("If the DigestAlgorithmIdentifier is id-PBMAC1, then " +
            "the parameters field must contain valid PBMAC1-params parameters.");
      }

      if (PKCSObjectIdentifiers.id_PBKDF2.equals(
          pbmac1Params.getKeyDerivationFunc().getAlgorithm())) {
        PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(
            pbmac1Params.getKeyDerivationFunc().getParameters());

        if (pbkdf2Params.getKeyLength() == null) {
          throw new IOException("Key length must be present when using PBMAC1.");
        }

        final HMac hMac = new HMac(getPrf(pbmac1Params.getMessageAuthScheme().getAlgorithm()));

        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator(
            getPrf(pbkdf2Params.getPrf().getAlgorithm()));

        generator.init(Strings.toUTF8ByteArray(password), pbkdf2Params.getSalt(),
            BigIntegers.intValueExact(pbkdf2Params.getIterationCount()));

        CipherParameters key = generator.generateDerivedParameters(
            BigIntegers.intValueExact(pbkdf2Params.getKeyLength()) * 8);

        Arrays.clear(generator.getPassword());

        hMac.init(key);
        hMac.update(data, 0, data.length);
        byte[] res = new byte[hMac.getMacSize()];
        hMac.doFinal(res, 0);
        return res;
      }
    }

    PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);
    PKCS12Key key = new PKCS12Key(password, wrongPkcs12Zero);

    try {
      Mac mac = helper.createMac(oid.getId());
      mac.init(key, defParams);
      mac.update(data);
      return mac.doFinal();
    } finally {
      Arrays.clear(key.getPassword());
    }
  }

  private static Digest getPrf(ASN1ObjectIdentifier prfId) {
    if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(prfId)) {
      return new SHA256Digest();
    } else if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(prfId)) {
      return new SHA512Digest();
    } else {
      throw new IllegalArgumentException("unknown prf id " + prfId);
    }
  }

  public static BridgeKeyPairBytes generateMlkemKeyPair(
      BridgeMlkemVariant variant, SecureRandom rnd) {
    Objects.requireNonNull(variant, "variant shall not be null");
    MLKEMKeyPairGenerator kpGen = new MLKEMKeyPairGenerator();
    MLKEMParameters mlkemParams =
          variant == BridgeMlkemVariant.mlkem512 ? MLKEMParameters.ml_kem_512
        : variant == BridgeMlkemVariant.mlkem768 ? MLKEMParameters.ml_kem_768
        : MLKEMParameters.ml_kem_1024;
    MLKEMKeyGenerationParameters params = new MLKEMKeyGenerationParameters( rnd, mlkemParams);
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
    return new MLKEMExtractor(priParams).extractSecret(encapsulatedKey);
  }

  public static byte[] crmfDecryptEncryptedKey(
      CertifiedKeyPair certifiedKeyPair, CmpCallback callback)
      throws GeneralSecurityException {
    return (certifiedKeyPair.getPrivateKey() == null) ? null
        : callback.decrypt(certifiedKeyPair.getPrivateKey());
  }

}
