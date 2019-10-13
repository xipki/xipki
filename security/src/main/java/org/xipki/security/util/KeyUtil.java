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

package org.xipki.security.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.EdECConstants;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

/**
 * Key utility class.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyUtil {

  private static final byte[]  x25519Prefix = Hex.decode("302a300506032b656e032100");
  private static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");
  private static final byte[]    x448Prefix = Hex.decode("3042300506032b656f033900");
  private static final byte[]   Ed448Prefix = Hex.decode("3043300506032b6571033a00");

  private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

  private static final Map<String, KeyPairGenerator> KEYPAIR_GENERATORS = new HashMap<>();

  private KeyUtil() {
  }

  public static KeyStore getKeyStore(String storeType) throws KeyStoreException {
    Args.notBlank(storeType, "storeType");
    if ("JKS".equalsIgnoreCase(storeType) || "JCEKS".equalsIgnoreCase(storeType)) {
      return KeyStore.getInstance(storeType);
    } else {
      try {
        return KeyStore.getInstance(storeType, "BC");
      } catch (KeyStoreException | NoSuchProviderException ex) {
        return KeyStore.getInstance(storeType);
      }
    }
  }

  // CHECKSTYLE:SKIP
  public static KeyPair generateRSAKeypair(int keysize, BigInteger publicExponent,
      SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException,
      InvalidAlgorithmParameterException {
    BigInteger tmpPublicExponent = publicExponent;
    if (tmpPublicExponent == null) {
      tmpPublicExponent = RSAKeyGenParameterSpec.F4;
    }
    AlgorithmParameterSpec params = new RSAKeyGenParameterSpec(keysize, tmpPublicExponent);
    KeyPairGenerator kpGen = getKeyPairGenerator("RSA");
    synchronized (kpGen) {
      if (random == null) {
        kpGen.initialize(params);
      } else {
        kpGen.initialize(params, random);
      }
      return kpGen.generateKeyPair();
    }
  }

  // CHECKSTYLE:SKIP
  public static KeyPair generateDSAKeypair(int plength, int qlength, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    DSAParameterSpec dsaParamSpec = DSAParameterCache.getDSAParameterSpec(plength, qlength,
        random);
    KeyPairGenerator kpGen = getKeyPairGenerator("DSA");
    synchronized (kpGen) {
      kpGen.initialize(dsaParamSpec, random);
      return kpGen.generateKeyPair();
    }
  }

  // CHECKSTYLE:SKIP
  public static KeyPair generateDSAKeypair(DSAParameters dsaParams, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    DSAParameterSpec dsaParamSpec = new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(),
        dsaParams.getG());
    return generateDSAKeypair(dsaParamSpec, random);
  }

  // CHECKSTYLE:SKIP
  public static KeyPair generateDSAKeypair(DSAParameterSpec dsaParamSpec, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    KeyPairGenerator kpGen = getKeyPairGenerator("DSA");
    synchronized (kpGen) {
      kpGen.initialize(dsaParamSpec, random);
      return kpGen.generateKeyPair();
    }
  }

  // CHECKSTYLE:SKIP
  public static DSAPublicKey generateDSAPublicKey(DSAPublicKeySpec keySpec)
      throws InvalidKeySpecException {
    Args.notNull(keySpec, "keySpec");
    KeyFactory kf = getKeyFactory("DSA");
    synchronized (kf) {
      return (DSAPublicKey) kf.generatePublic(keySpec);
    }
  }

  // CHECKSTYLE:SKIP
  public static KeyPair generateEdECKeypair(ASN1ObjectIdentifier curveId, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    Args.notNull(curveId, "curveId");
    String algorithm = EdECConstants.getName(curveId);
    KeyPairGenerator kpGen = getKeyPairGenerator(algorithm);
    synchronized (kpGen) {
      if (random != null) {
        kpGen.initialize(EdECConstants.getKeyBitSize(curveId), random);
      }
      return kpGen.generateKeyPair();
    }
  }

  // CHECKSTYLE:SKIP
  public static KeyPair generateECKeypair(ASN1ObjectIdentifier curveId, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    Args.notNull(curveId, "curveId");

    ECGenParameterSpec spec = new ECGenParameterSpec(curveId.getId());
    KeyPairGenerator kpGen = getKeyPairGenerator("EC");
    synchronized (kpGen) {
      if (random == null) {
        kpGen.initialize(spec);
      } else {
        kpGen.initialize(spec, random);
      }
      return kpGen.generateKeyPair();
    }
  }

  /**
   * Convert XDH edwards private key to EdDSA private key. As the name indicates,
   * the converted key is dummy, you cannot verify the signature signed with
   * the converted private key against the correspond public key.
   * @param key XDH private key
   * @return the corresponding EdDSA private key (dummy)
   * @throws InvalidKeySpecException
   *           If key is invalid.
   */
  // CHECKSTYLE:SKIP
  public static PrivateKey convertXDHToDummyEdDSAPrivateKey(PrivateKey key)
      throws InvalidKeySpecException {
    if (key instanceof XDHKey && key instanceof PrivateKey) {
      PrivateKeyInfo xdhPki = PrivateKeyInfo.getInstance(key.getEncoded());
      String xdhAlgo = key.getAlgorithm();

      try {
        PrivateKeyInfo edPki;
        if (xdhAlgo.equalsIgnoreCase(EdECConstants.X25519)) {
          edPki = new PrivateKeyInfo(
              new AlgorithmIdentifier(EdECConstants.id_Ed25519), xdhPki.parsePrivateKey());
        } else if (xdhAlgo.equalsIgnoreCase(EdECConstants.X448)) {
          byte[] x448Octets = ASN1OctetString.getInstance(xdhPki.parsePrivateKey()).getOctets();
          byte[] ed448Octets = new byte[57];
          System.arraycopy(x448Octets, 0, ed448Octets, 0, 56);

          edPki = new PrivateKeyInfo(
              new AlgorithmIdentifier(EdECConstants.id_Ed448),
              new DEROctetString(ed448Octets));
        } else {
          throw new IllegalArgumentException("unknown key algorithm " + xdhAlgo);
        }

        byte[] encoded = edPki.getEncoded();
        return getKeyFactory("EDDSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
      } catch (IOException ex) {
        throw new InvalidKeySpecException("could not convert XDH to EdDSA private key", ex);
      }
    } else {
      throw new IllegalArgumentException("key is not an XDH private key");
    }
  } // method convertXDHToDummyEdDSAPrivateKey

  private static KeyFactory getKeyFactory(String algorithm) throws InvalidKeySpecException {
    String alg = algorithm.toUpperCase();
    if ("ECDSA".equals(alg)) {
      alg = "EC";
    }
    synchronized (KEY_FACTORIES) {
      KeyFactory kf = KEY_FACTORIES.get(algorithm);
      if (kf != null) {
        return kf;
      }

      try {
        kf = KeyFactory.getInstance(algorithm, "BC");
      } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
        throw new InvalidKeySpecException("could not find KeyFactory for " + algorithm
            + ": " + ex.getMessage());
      }
      KEY_FACTORIES.put(algorithm, kf);
      return kf;
    }
  } // method getKeyFactory

  private static KeyPairGenerator getKeyPairGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    String alg = algorithm.toUpperCase();
    if ("ECDSA".equals(alg)) {
      alg = "EC";
    }
    synchronized (KEYPAIR_GENERATORS) {
      KeyPairGenerator kg = KEYPAIR_GENERATORS.get(algorithm);
      if (kg != null) {
        return kg;
      }

      kg = KeyPairGenerator.getInstance(algorithm, "BC");
      KEYPAIR_GENERATORS.put(algorithm, kg);
      return kg;
    }
  } // method getKeyPairGenerator

  public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
      throws InvalidKeySpecException {
    Args.notNull(pkInfo, "pkInfo");

    X509EncodedKeySpec keyspec;
    try {
      keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
    ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

    String algorithm;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
      algorithm = "RSA";
    } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
      algorithm = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
      algorithm = "EC";
    } else {
      algorithm = EdECConstants.getName(pkInfo.getAlgorithm().getAlgorithm());
    }

    if (algorithm == null) {
      throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
    }

    KeyFactory kf = getKeyFactory(algorithm);
    synchronized (kf) {
      return kf.generatePublic(keyspec);
    }
  } // method generatePublicKey

  // CHECKSTYLE:SKIP
  public static RSAPublicKey generateRSAPublicKey(RSAPublicKeySpec keySpec)
      throws InvalidKeySpecException {
    Args.notNull(keySpec, "keySpec");
    KeyFactory kf = getKeyFactory("RSA");
    synchronized (kf) {
      return (RSAPublicKey) kf.generatePublic(keySpec);
    }
  }

  public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
      throws InvalidKeyException {
    Args.notNull(key, "key");

    if (key instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
      return new RSAPrivateCrtKeyParameters(rsaKey.getModulus(),
        rsaKey.getPublicExponent(), rsaKey.getPrivateExponent(),
        rsaKey.getPrimeP(), rsaKey.getPrimeQ(), rsaKey.getPrimeExponentP(),
        rsaKey.getPrimeExponentQ(), rsaKey.getCrtCoefficient());
    } else if (key instanceof RSAPrivateKey) {
      RSAPrivateKey rsaKey = (RSAPrivateKey) key;
      return new RSAKeyParameters(true, rsaKey.getModulus(), rsaKey.getPrivateExponent());
    } else if (key instanceof ECPrivateKey) {
      return ECUtil.generatePrivateKeyParameter(key);
    } else if (key instanceof DSAPrivateKey) {
      return DSAUtil.generatePrivateKeyParameter(key);
    } else if (key instanceof XDHKey || key instanceof EdDSAKey) {
      try {
        return PrivateKeyFactory.createKey(key.getEncoded());
      } catch (IOException ex) {
        throw new InvalidKeyException("exception creating key: " + ex.getMessage(), ex);
      }
    } else {
      throw new InvalidKeyException("unknown key " + key.getClass().getName());
    }
  } // method generatePrivateKeyParameter

  public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
      throws InvalidKeyException {
    Args.notNull(key, "key");

    if (key instanceof RSAPublicKey) {
      RSAPublicKey rsaKey = (RSAPublicKey) key;
      return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
    } else if (key instanceof ECPublicKey) {
      return ECUtil.generatePublicKeyParameter(key);
    } else if (key instanceof DSAPublicKey) {
      return DSAUtil.generatePublicKeyParameter(key);
    } else if (key instanceof XDHKey || key instanceof EdDSAKey) {
      byte[] encoded = key.getEncoded();
      String algorithm = key.getAlgorithm();
      if (EdECConstants.X25519.equalsIgnoreCase(algorithm)) {
        return new X25519PublicKeyParameters(encoded, encoded.length - 32);
      } else if (EdECConstants.Ed25519.equalsIgnoreCase(algorithm)) {
        return new Ed25519PublicKeyParameters(encoded, encoded.length - 32);
      } else if (EdECConstants.X448.equalsIgnoreCase(algorithm)) {
        return new X448PublicKeyParameters(encoded, encoded.length - 56);
      } else if (EdECConstants.Ed448.equalsIgnoreCase(algorithm)) {
        return new Ed448PublicKeyParameters(encoded, encoded.length - 57);
      } else {
        throw new InvalidKeyException("unknown Edwards key " + algorithm);
      }
    } else {
      throw new InvalidKeyException("unknown key " + key.getClass().getName());
    }
  } // method generatePublicKeyParameter

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
      throws InvalidKeyException {
    Args.notNull(publicKey, "publicKey");

    if (publicKey instanceof DSAPublicKey) {
      DSAPublicKey dsaPubKey = (DSAPublicKey) publicKey;
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new ASN1Integer(dsaPubKey.getParams().getP()));
      vec.add(new ASN1Integer(dsaPubKey.getParams().getQ()));
      vec.add(new ASN1Integer(dsaPubKey.getParams().getG()));
      ASN1Sequence dssParams = new DERSequence(vec);

      try {
        return new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dssParams),
            new ASN1Integer(dsaPubKey.getY()));
      } catch (IOException ex) {
        throw new InvalidKeyException(ex.getMessage(), ex);
      }
    } else if (publicKey instanceof RSAPublicKey) {
      RSAPublicKey rsaPubKey = (RSAPublicKey) publicKey;
      try {
        return new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(rsaPubKey.getModulus(),
                rsaPubKey.getPublicExponent()));
      } catch (IOException ex) {
        throw new InvalidKeyException(ex.getMessage(), ex);
      }
    } else if (publicKey instanceof ECPublicKey) {
      ECPublicKey ecPubKey = (ECPublicKey) publicKey;

      ECParameterSpec paramSpec = ecPubKey.getParams();
      ASN1ObjectIdentifier curveOid = detectCurveOid(paramSpec);
      if (curveOid == null) {
        throw new InvalidKeyException("Cannot find namedCurve of the given private key");
      }

      java.security.spec.ECPoint pointW = ecPubKey.getW();
      BigInteger wx = pointW.getAffineX();
      if (wx.signum() != 1) {
        throw new InvalidKeyException("Wx is not positive");
      }

      BigInteger wy = pointW.getAffineY();
      if (wy.signum() != 1) {
        throw new InvalidKeyException("Wy is not positive");
      }

      int keysize = (paramSpec.getOrder().bitLength() + 7) / 8;
      byte[] wxBytes = BigIntegers.asUnsignedByteArray(keysize, wx);
      byte[] wyBytes = BigIntegers.asUnsignedByteArray(keysize, wy);
      byte[] pubKey = new byte[1 + keysize * 2];
      pubKey[0] = 4; // uncompressed
      System.arraycopy(wxBytes, 0, pubKey, 1, keysize);
      System.arraycopy(wyBytes, 0, pubKey, 1 + keysize, keysize);

      AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
          curveOid);
      return new SubjectPublicKeyInfo(algId, pubKey);
    } else if (publicKey instanceof XDHKey || publicKey instanceof EdDSAKey) {
      String algorithm = publicKey.getAlgorithm();
      byte[] encoded = publicKey.getEncoded();

      int keysize;
      byte[] prefix;
      ASN1ObjectIdentifier algOid;
      if (EdECConstants.Ed25519.equalsIgnoreCase(algorithm)) {
        algOid = EdECConstants.id_Ed25519;
        keysize = 32;
        prefix = Ed25519Prefix;
      } else if (EdECConstants.X25519.equalsIgnoreCase(algorithm)) {
        algOid = EdECConstants.id_X25519;
        keysize = 32;
        prefix = x25519Prefix;
      } else if (EdECConstants.Ed448.equalsIgnoreCase(algorithm)) {
        algOid = EdECConstants.id_Ed448;
        keysize = 57;
        prefix = Ed448Prefix;
      } else if (EdECConstants.X448.equalsIgnoreCase(algorithm)) {
        algOid = EdECConstants.id_X448;
        keysize = 56;
        prefix = x448Prefix;
      } else {
        throw new IllegalArgumentException("invalid algorithm " + algorithm);
      }

      if (encoded.length != prefix.length + keysize) {
        throw new IllegalArgumentException("invalid encoded PublicKey");
      }

      if (!CompareUtil.areEqual(encoded, 0, prefix, 0, prefix.length)) {
        throw new IllegalArgumentException("invalid encoded PublicKey");
      }

      byte[] keyData = Arrays.copyOfRange(encoded, prefix.length, prefix.length + keysize);
      AlgorithmIdentifier algId = new AlgorithmIdentifier(algOid);
      return new SubjectPublicKeyInfo(algId, keyData);
    } else {
      throw new InvalidKeyException("unknown publicKey class " + publicKey.getClass().getName());
    }
  } // method createSubjectPublicKeyInfo

  // CHECKSTYLE:SKIP
  public static ECPublicKey createECPublicKey(byte[] encodedAlgorithmIdParameters,
      byte[] encodedPoint) throws InvalidKeySpecException {
    Args.notNull(encodedAlgorithmIdParameters, "encodedAlgorithmIdParameters");
    Args.notNull(encodedPoint, "encodedPoint");

    ASN1Encodable algParams;
    if (encodedAlgorithmIdParameters[0] == 6) {
      algParams = ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters);
    } else {
      algParams = X962Parameters.getInstance(encodedAlgorithmIdParameters);
    }
    AlgorithmIdentifier algId = new AlgorithmIdentifier(
        X9ObjectIdentifiers.id_ecPublicKey, algParams);

    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, encodedPoint);
    X509EncodedKeySpec keySpec;
    try {
      keySpec = new X509EncodedKeySpec(spki.getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }

    KeyFactory kf;
    try {
      kf = KeyFactory.getInstance("EC", "BC");
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
    return (ECPublicKey) kf.generatePublic(keySpec);
  } // method createECPublicKey

  private static ASN1ObjectIdentifier detectCurveOid(ECParameterSpec paramSpec) {
    org.bouncycastle.jce.spec.ECParameterSpec bcParamSpec = EC5Util.convertSpec(paramSpec);
    return ECUtil.getNamedCurveOid(bcParamSpec);
  }

  // CHECKSTYLE:SKIP
  public static byte[] getUncompressedEncodedECPoint(ECPoint point, int orderBitLength) {
    int orderByteLength = (orderBitLength + 7) / 8;
    byte[] keyData = new byte[1 + orderByteLength * 2];
    keyData[0] = 4;
    unsignedByteArrayCopy(keyData, 1, orderByteLength, point.getAffineX());
    unsignedByteArrayCopy(keyData, 1 + orderByteLength, orderByteLength, point.getAffineY());
    return keyData;
  } // method getUncompressedEncodedECPoint

  /**
   * Write the passed in value as an unsigned byte array to the {@code out} from offset
   * {@code outOffset}.
   *
   * @param value value to be converted.
   * @return a byte array without a leading zero byte if present in the signed encoding.
   */
  private static void unsignedByteArrayCopy(byte[] dest, int destPos,
      int length, BigInteger value) {
    byte[] bytes = value.toByteArray();
    if (bytes.length == length) {
      System.arraycopy(bytes, 0, dest, destPos, length);
    } else {
      int start = bytes[0] == 0 ? 1 : 0;
      int count = bytes.length - start;

      if (count > length) {
        throw new IllegalArgumentException("standard length exceeded for value");
      }

      System.arraycopy(bytes, start, dest, destPos + length - count, count);
    }
  } // method unsignedByteArrayCopy

}
