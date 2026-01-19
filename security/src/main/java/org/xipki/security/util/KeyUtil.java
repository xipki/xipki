// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
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
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.util.BigIntegers;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.HashAlgo;
import org.xipki.security.KemEncapKey;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.bc.XiECContentVerifierProviderBuilder;
import org.xipki.security.bc.XiEdDSAContentVerifierProvider;
import org.xipki.security.bc.XiKEMContentVerifierProvider;
import org.xipki.security.bc.XiMLDSASigContentVerifierProvider;
import org.xipki.security.bc.XiRSAContentVerifierProviderBuilder;
import org.xipki.security.bc.XiXDHContentVerifierProvider;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs12.KeyPairWithSubjectPublicKeyInfo;
import org.xipki.security.pkcs12.KeyStoreWrapper;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12ContentSignerBuilder;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.asn1.Asn1Util;
import org.xipki.util.extra.misc.NopOutputStream;
import org.xipki.util.extra.misc.RandomUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Key utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class KeyUtil {

  private static final BigInteger bnSm2primev1Order = new BigInteger(
      "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
      16);

  private static final byte[] sm2CurveData = Hex.decode(
      "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc" + // A
      "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93" + // B
      "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" + // Gx
      "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"); // Gy

  private static final byte[] sm2DefaultIDA =
      new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

  private static final Map<String, BcContentVerifierProviderBuilder>
      VERIFIER_PROVIDER_BUILDER = new HashMap<>();

  public static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      OIDs.Algo.id_rsaEncryption, DERNull.INSTANCE);

  private KeyUtil() {
  }

  public static byte[] getSM2Z(byte[] userID, BigInteger pubPointX,
                               BigInteger pubPointY) {
    SM3Digest digest = new SM3Digest();

    if (userID == null) {
      digest.update((byte) 0x00);
      digest.update((byte) 0x80);
      digest.update(sm2DefaultIDA, 0, sm2DefaultIDA.length);
    } else {
      if (userID.length > 0x1FFF) {
        throw new IllegalArgumentException("userId too long");
      }

      int len = userID.length * 8;
      digest.update((byte)(len >> 8));
      digest.update((byte)(len & 0xFF));
      digest.update(userID, 0, userID.length);
    }

    digest.update(sm2CurveData, 0, sm2CurveData.length);

    digest.update(BigIntegers.asUnsignedByteArray(32, pubPointX), 0, 32);
    digest.update(BigIntegers.asUnsignedByteArray(32, pubPointY), 0, 32);

    byte[] result = new byte[digest.getDigestSize()];
    digest.doFinal(result, 0);
    return result;
  } // method getSM2Z

  public static boolean isSm2primev1Curve(BigInteger curveOrder) {
    return bnSm2primev1Order.equals(curveOrder);
  }

  public static byte[] kmacDerive(
      SecretKey ikm, int keyByteSize, byte[] info, byte[] data) {
    return kmacDerive(ikm.getEncoded(), keyByteSize, info, data);
  }

  public static byte[] kmacDerive(
      byte[] ikm, int keyByteSize, byte[] info, byte[] data) {
    KMAC kmac = new KMAC(256, info);
    KeyParameter keyParameter = new KeyParameter(ikm, 0, ikm.length);
    kmac.init(keyParameter);
    kmac.update(data, 0, data.length);

    byte[] outKey = new byte[keyByteSize];
    kmac.doFinal(outKey, 0, keyByteSize);
    return outKey;
  }

  public static KeyStore getInKeyStore(String storeType)
      throws KeyStoreException {
    return getKeyStore(storeType, "BC");
  }

  public static KeyStore getOutKeyStore(String storeType)
      throws KeyStoreException {
    return getKeyStore(storeType, "SunJSSE");
  }

  private static KeyStore getKeyStore(String storeType, String pkcs12Provider)
      throws KeyStoreException {
    if (StringUtil.orEqualsIgnoreCase(
        Args.notBlank(storeType, "storeType"), "PKCS12", "PKCS#12")) {
      try {
        return KeyStore.getInstance(storeType, pkcs12Provider);
      } catch (KeyStoreException | NoSuchProviderException ex) {
        return KeyStore.getInstance(storeType);
      }
    } else {
      return KeyStore.getInstance(storeType);
    }
  }

  public static KeyPair generateKeypair(KeySpec keySpec, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      InvalidAlgorithmParameterException {
    switch (keySpec) {
      case RSA2048:
      case RSA3072:
      case RSA4096: {
        KeyPairGenerator kpGen = getKeyPairGenerator("RSA");
        assert keySpec.getRSAKeyBitSize() != null;
        int keyBitSize = keySpec.getRSAKeyBitSize();
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
            : keySpec == KeySpec.X25519 ? "X25519"
            : "X448";

        int keyBitSize = keySpec == KeySpec.ED25519 ? 256
            : keySpec == KeySpec.ED448 ? 448
            : keySpec == KeySpec.X25519 ? 256
            : 448;

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
        MLDSAParameterSpec spec =
            (keySpec == KeySpec.MLDSA44) ? MLDSAParameterSpec.ml_dsa_44
            : keySpec == KeySpec.MLDSA65 ? MLDSAParameterSpec.ml_dsa_65
            : MLDSAParameterSpec.ml_dsa_87;

        KeyPairGenerator kpGen = getKeyPairGenerator("ML-DSA");
        if (random == null) {
          kpGen.initialize(spec);
        } else {
          kpGen.initialize(spec, random);
        }

        return kpGen.generateKeyPair();
      }
      case MLKEM512:
      case MLKEM768:
      case MLKEM1024: {
        MLKEMParameterSpec spec =
            (keySpec == KeySpec.MLKEM512) ? MLKEMParameterSpec.ml_kem_512
            : keySpec == KeySpec.MLKEM768 ? MLKEMParameterSpec.ml_kem_768
            : MLKEMParameterSpec.ml_kem_1024;

        KeyPairGenerator kpGen = getKeyPairGenerator("ML-KEM");
        if (random == null) {
          kpGen.initialize(spec);
        } else {
          kpGen.initialize(spec, random);
        }

        return kpGen.generateKeyPair();
      }
      case SECP256R1:
      case SECP384R1:
      case SECP521R1:
      case BRAINPOOLP256R1:
      case BRAINPOOLP384R1:
      case BRAINPOOLP512R1:
      case SM2P256V1:
      case FRP256V1: {
        EcCurveEnum curve = keySpec.getEcCurve();
        assert curve != null;
        ECGenParameterSpec spec =
            new ECGenParameterSpec(curve.getOid().getId());
        KeyPairGenerator kpGen = getKeyPairGenerator("EC");
        if (random == null) {
          kpGen.initialize(spec);
        } else {
          kpGen.initialize(spec, random);
        }
        return kpGen.generateKeyPair();
      }
      default: {
        throw new IllegalStateException("unknown keyspec " + keySpec);
      }
    }
  }

  public static KeyPairWithSubjectPublicKeyInfo generateKeypair2(
      KeySpec keySpec, SecureRandom random) throws Exception {
    KeyPair keypair = KeyUtil.generateKeypair(keySpec, random);

    switch (keySpec) {
      case RSA2048:
      case RSA3072:
      case RSA4096: {
        java.security.interfaces.RSAPublicKey rsaPubKey =
            (java.security.interfaces.RSAPublicKey) keypair.getPublic();

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
            keySpec.getAlgorithmIdentifier(),
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(rsaPubKey.getModulus(),
                rsaPubKey.getPublicExponent()));
        return new KeyPairWithSubjectPublicKeyInfo(keypair, spki);
      }
      case ED25519:
      case ED448:
      case X25519:
      case X448:
      case MLDSA44:
      case MLDSA65:
      case MLDSA87:
      case MLKEM512:
      case MLKEM768:
      case MLKEM1024: {
        SubjectPublicKeyInfo subjectPublicKeyInfo =
            KeyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
        return new KeyPairWithSubjectPublicKeyInfo(keypair,
            subjectPublicKeyInfo);
      }
      case SECP256R1:
      case SECP384R1:
      case SECP521R1:
      case BRAINPOOLP256R1:
      case BRAINPOOLP384R1:
      case BRAINPOOLP512R1:
      case SM2P256V1:
      case FRP256V1: {
        ECPublicKey pub = (ECPublicKey) keypair.getPublic();
        int fieldBitSize = pub.getParams().getCurve().getField().getFieldSize();
        byte[] keyData = KeyUtil.getUncompressedEncodedECPoint(
            pub.getW(), fieldBitSize);

        SubjectPublicKeyInfo subjectPublicKeyInfo =
            new SubjectPublicKeyInfo(keySpec.getAlgorithmIdentifier(),
                keyData);
        return new KeyPairWithSubjectPublicKeyInfo(keypair,
            subjectPublicKeyInfo);
      }
      default: {
        throw new IllegalStateException("unknown keyspec " + keySpec);
      }
    }
  }

  public static KeyStoreWrapper generateKeypair3(
      KeySpec keySpec, KeystoreGenerationParameters params)
      throws Exception {
    KeyPairWithSubjectPublicKeyInfo kp =
        generateKeypair2(keySpec, params.getRandom());

    // 10 minutes past
    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
    Instant notAfter = notBefore.plus(3650, ChronoUnit.DAYS);

    String dnStr = "CN=DUMMY";
    X500Name subjectDn = new X500Name(dnStr);
    SubjectPublicKeyInfo subjectPublicKeyInfo = kp.getSubjectPublicKeyInfo();
    ContentSigner contentSigner = getContentSigner(kp.getKeypair().getPrivate(),
        kp.getKeypair().getPublic(), params.getRandom());

    // Generate keystore
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
        subjectDn, BigInteger.ONE, Date.from(notBefore), Date.from(notAfter),
        subjectDn, subjectPublicKeyInfo);

    byte[] encodedSpki =
        kp.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

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

    X509Cert cert = new X509Cert(certGenerator.build(contentSigner));

    KeyStore ks = KeyUtil.getOutKeyStore("PKCS12");
    ks.load(null, params.getPassword());

    ks.setKeyEntry("main", kp.getKeypair().getPrivate(),
        params.getPassword(),
        new java.security.cert.Certificate[]{cert.toJceCert()});

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.getPassword());
    } finally {
      ksStream.flush();
    }

    KeyStoreWrapper result = new KeyStoreWrapper(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    result.setSubjectPublicKeyInfo(kp.getSubjectPublicKeyInfo());
    return result;
  } // method generateKeypair3

  public static KeyStoreWrapper generateSecretKey(
      String algorithm, int keyBitLen, KeystoreGenerationParameters params)
      throws Exception {
    if (keyBitLen % 8 != 0) {
      throw new IllegalArgumentException("keyBitLen (" + keyBitLen +
          ") must be multiple of 8");
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

  private static KeyPairGenerator getKeyPairGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    if ("RSA".equalsIgnoreCase(algorithm)) {
      return KeyPairGenerator.getInstance(algorithm);
    } else {
      if ("ECDSA".equalsIgnoreCase(algorithm)) {
        algorithm = "EC";
      }

      return KeyPairGenerator.getInstance(algorithm, "BC");
    }
  } // method getKeyPairGenerator

  public static PrivateKey getPrivateKey(PrivateKeyInfo pkInfo)
      throws InvalidKeySpecException {
    try {
      return BouncyCastleProvider.getPrivateKey(pkInfo);
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
  }

  public static PublicKey getPublicKey(SubjectPublicKeyInfo pkInfo)
      throws InvalidKeySpecException {
    try {
      return BouncyCastleProvider.getPublicKey(pkInfo);
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
  }

  public static RSAPublicKey getRSAPublicKey(RSAPublicKeySpec keySpec)
      throws InvalidKeySpecException {
    Args.notNull(keySpec, "keySpec");
    try {
      return (RSAPublicKey) KeyFactory.getInstance("RSA")
          .generatePublic(keySpec);
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidKeySpecException(
          "could not find KeyFactory for RSA: " + ex.getMessage());
    }
  }

  public static AsymmetricKeyParameter getPublicKeyParameter(PublicKey key)
      throws InvalidKeyException {
    Args.notNull(key, "key");

    if (key instanceof RSAPublicKey) {
      RSAPublicKey rsaKey = (RSAPublicKey) key;
      return new RSAKeyParameters(false, rsaKey.getModulus(),
          rsaKey.getPublicExponent());
    } else if (key instanceof ECPublicKey) {
      return ECUtil.generatePublicKeyParameter(key);
    } else if (key instanceof XDHKey || key instanceof EdDSAKey) {
      byte[] encoded = key.getEncoded();
      String algorithm = key.getAlgorithm().toUpperCase();
      switch (algorithm) {
        case "X25519":
          return new X25519PublicKeyParameters(encoded, encoded.length - 32);
        case "ED25519":
          return new Ed25519PublicKeyParameters(encoded, encoded.length - 32);
        case "X448":
          return new X448PublicKeyParameters(encoded, encoded.length - 56);
        case "ED448":
          return new Ed448PublicKeyParameters(encoded, encoded.length - 57);
        default:
          throw new InvalidKeyException("unknown Edwards key " + algorithm);
      }
    } else {
      throw new InvalidKeyException("unknown key " + key.getClass().getName());
    }
  } // method generatePublicKeyParameter

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(
      PublicKey publicKey) throws InvalidKeyException {
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
      byte[] pubKey = new byte[1 + keysize * 2];
      pubKey[0] = 4; // uncompressed
      System.arraycopy(wxBytes, 0, pubKey, 1, keysize);
      System.arraycopy(wyBytes, 0, pubKey, 1 + keysize, keysize);

      AlgorithmIdentifier algId =
          new AlgorithmIdentifier(OIDs.Algo.id_ecPublicKey, curveOid);
      return new SubjectPublicKeyInfo(algId, pubKey);
    } else {
      return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    }
  } // method createSubjectPublicKeyInfo

  public static ECPublicKey createECPublicKey(
      EcCurveEnum curve, byte[] encodedPoint)
      throws InvalidKeySpecException {
    return (ECPublicKey) getPublicKey(
        new SubjectPublicKeyInfo(curve.getAlgId(), encodedPoint));
  }

  public static ASN1ObjectIdentifier detectCurveOid(ECParameterSpec paramSpec) {
    byte[] ecParams = Optional.ofNullable(
        Functions.getEcParams(paramSpec.getOrder(),
            paramSpec.getGenerator().getAffineX())).orElseThrow(
                () -> new IllegalArgumentException("unknown paramSpec"));

    return new ASN1ObjectIdentifier(Asn1Util.decodeOid(ecParams));
  }

  public static byte[] getUncompressedEncodedECPoint(
      ECPoint point, int fieldBitSize) {
    int fieldByteSize = (fieldBitSize + 7) / 8;
    byte[] keyData = new byte[1 + fieldByteSize * 2];
    keyData[0] = 4;
    unsignedByteArrayCopy(keyData, 1, fieldByteSize,
        point.getAffineX());
    unsignedByteArrayCopy(keyData, 1 + fieldByteSize, fieldByteSize,
        point.getAffineY());
    return keyData;
  }

  /**
   * Write the passed in value as an unsigned byte array to the {@code dest}
   * from offset {@code destPos}.
   *
   * @param value value to be converted.
   * @param destPos destination
   */
  private static void unsignedByteArrayCopy(
      byte[] dest, int destPos, int length, BigInteger value) {
    byte[] bytes = value.toByteArray();
    if (bytes.length == length) {
      System.arraycopy(bytes, 0, dest, destPos, length);
    } else {
      int start = bytes[0] == 0 ? 1 : 0;
      int count = bytes.length - start;

      if (count > length) {
        throw new IllegalArgumentException(
            "value cannot be expressed in " + length + " bytes");
      }

      System.arraycopy(bytes, start, dest, destPos + length - count, count);
    }
  }

  public static KemEncapKey generateKemEncapKey(
      SubjectPublicKeyInfo spki, SecretKeyWithAlias masterKey)
      throws GeneralSecurityException {
    ASN1ObjectIdentifier algOid = spki.getAlgorithm().getAlgorithm();
    if (!(OIDs.Algo.id_ml_kem_512.equals(algOid) ||
        OIDs.Algo.id_ml_kem_768.equals(algOid) ||
        OIDs.Algo.id_ml_kem_1024.equals(algOid))) {
      throw new IllegalArgumentException(
          "The given public key (spki) is not an MLKEM key.");
    }

    byte[] rawPkData = spki.getPublicKeyData().getOctets();

    // derive the shared secret
    byte[] secret = kmacDerive(masterKey.getSecretKey(), 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);

    // Encapsulate the secret
    PublicKey publicKey = KeyUtil.getPublicKey(spki);
    Cipher wrapper = Cipher.getInstance("MLKEM", "BC");
    KTSParameterSpec spec = new KTSParameterSpec.Builder("AES-KWP", 256)
        .withNoKdf().build();
    wrapper.init(Cipher.WRAP_MODE, publicKey, spec);
    byte[] wrapped = wrapper.wrap(new SecretKeySpec(secret, "GENERAL"));

    return new KemEncapKey(masterKey.getAlias(), KemEncapKey.ALG_AES_KWP_256,
        wrapped);
  }

  public static Signer createPSSRSASigner(SignAlgo sigAlgo)
      throws XiSecurityException {
    if (!Args.notNull(sigAlgo, "sigAlgo").isRSAPSSSigAlgo()) {
      throw new XiSecurityException(sigAlgo + " is not an RSAPSS algorithm");
    }

    HashAlgo hashAlgo = sigAlgo.getHashAlgo();
    return new PSSSigner(new RSABlindedEngine(), hashAlgo.createDigest(),
        hashAlgo.createDigest(), hashAlgo.getLength(),
        org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT);
  } // method createPSSRSASigner

  public static ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey) throws InvalidKeyException {
    return getContentVerifierProvider(publicKey, null, null);
  }

  public static ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert,
      SecretKey ownerMasterKey) throws InvalidKeyException {
    String keyAlg = Args.notNull(publicKey, "publicKey")
        .getAlgorithm().toUpperCase();

    keyAlg = keyAlg.replace("-", "");

    switch (keyAlg) {
      case "ED25519":
      case "ED448":
        return new XiEdDSAContentVerifierProvider(publicKey);
      case "X25519":
      case "X448":
        if (ownerKeyAndCert == null) {
          throw new InvalidKeyException(
              "ownerKeyAndCert is required but absent");
        }
        return new XiXDHContentVerifierProvider(publicKey, ownerKeyAndCert);
      case "MLDSA44":
      case "MLDSA65":
      case "MLDSA87":
        return new XiMLDSASigContentVerifierProvider(publicKey);
      case "MLKEM512":
      case "MLKEM768":
      case "MLKEM1024":
        if (ownerMasterKey == null) {
          throw new InvalidKeyException(
              "ownerMasterKey is required but absent");
        }
        return new XiKEMContentVerifierProvider(publicKey, ownerMasterKey);
    }

    BcContentVerifierProviderBuilder builder =
        VERIFIER_PROVIDER_BUILDER.get(keyAlg);

    if (builder == null) {
      switch (keyAlg) {
        case "RSA":
          builder = new XiRSAContentVerifierProviderBuilder();
          break;
        case "EC":
        case "ECDSA":
          builder = new XiECContentVerifierProviderBuilder();
          break;
        default:
          throw new InvalidKeyException(
              "unknown key algorithm of the public key " + keyAlg);
      }
      VERIFIER_PROVIDER_BUILDER.put(keyAlg, builder);
    }

    AsymmetricKeyParameter keyParam = KeyUtil.getPublicKeyParameter(publicKey);
    try {
      return builder.build(keyParam);
    } catch (OperatorCreationException ex) {
      throw new InvalidKeyException("could not build ContentVerifierProvider: "
          + ex.getMessage(), ex);
    }
  } // method getContentVerifierProvider

  public static ContentSigner getContentSigner(
      PrivateKey key, PublicKey publicKey, SecureRandom random)
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
            :  orderBitLength > 160 ? SignAlgo.ECDSA_SHA256
            :  SignAlgo.ECDSA_SHA1;
      }
    } else if (key instanceof MLDSAPrivateKey) {
      SubjectPublicKeyInfo spki =
          SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      algo = SignAlgo.getInstance(spki.getAlgorithm());
    } else {
      SubjectPublicKeyInfo spki =
          SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      KeySpec keySpec = KeySpec.ofPublicKey(spki);
      if (keySpec == null) {
        throw new IllegalArgumentException("unknown public key algorithm "
            + spki.getAlgorithm().getAlgorithm());
      }

      if (keySpec.isMontgomeryEC()) {
        // Just dummy: signature created by the signKey cannot be verified
        // by the public key.
        SignAlgo signAlgo = (keySpec == KeySpec.X25519)
            ? SignAlgo.ED25519 : SignAlgo.ED448;

        return new ContentSigner() {
          @Override
          public AlgorithmIdentifier getAlgorithmIdentifier() {
            return signAlgo.getAlgorithmIdentifier();
          }

          @Override
          public OutputStream getOutputStream() {
            return new NopOutputStream();
          }

          @Override
          public byte[] getSignature() {
            return new byte[(keySpec == KeySpec.X25519) ? 64 : 114];
          }
        };
      } else if (keySpec.isEdwardsEC()) {
        algo = (keySpec == KeySpec.ED25519) ? SignAlgo.ED25519 : SignAlgo.ED448;
      } else if (keySpec == KeySpec.MLKEM512
          || keySpec == KeySpec.MLKEM768
          || keySpec == KeySpec.MLKEM1024) {
        // just return dummy signer
        return new ContentSigner() {
          @Override
          public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4"));
          }

          @Override
          public OutputStream getOutputStream() {
            return new NopOutputStream();
          }

          @Override
          public byte[] getSignature() {
            return new byte[64];
          }
        };
      } else if (keySpec == KeySpec.MLDSA44) {
        algo = SignAlgo.ML_DSA_44;
      } else if (keySpec == KeySpec.MLDSA65) {
        algo = SignAlgo.ML_DSA_65;
      } else if (keySpec == KeySpec.MLDSA87) {
        algo = SignAlgo.ML_DSA_87;
      } else {
        throw new IllegalArgumentException("unknown key-spec " + keySpec);
      }
    }

    P12ContentSignerBuilder builder =
        new P12ContentSignerBuilder(key, publicKey);
    ConcurrentContentSigner csigner = builder.createSigner(algo, 1, random);
    return csigner.borrowSigner();
  } // method getContentSigner

  public static SubjectPublicKeyInfo getPublicKeyOfFirstKeyEntry(
      String keystoreType, String keystorePath, char[] keystorePassword)
      throws XiSecurityException {
    try (InputStream is = new FileInputStream(
        IoUtil.expandFilepath(keystorePath))) {
      KeyStore p12 = KeyUtil.getInKeyStore(keystoreType);
      p12.load(is, keystorePassword);

      Enumeration<String> aliases = p12.aliases();
      String keyAlias = null;
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (p12.isKeyEntry(alias)) {
          keyAlias = alias;
          break;
        }
      }

      Certificate cert = Certificate.getInstance(
          p12.getCertificate(keyAlias).getEncoded());
      return cert.getSubjectPublicKeyInfo();
    } catch (Exception e) {
      throw new XiSecurityException(e);
    }
  }

}
