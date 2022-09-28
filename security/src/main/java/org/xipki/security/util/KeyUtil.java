/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.EdECConstants;
import org.xipki.util.CompareUtil;
import org.xipki.util.StringUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Key utility class.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyUtil {

  public static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

  private static final byte[]  x25519Prefix = Hex.decode("302a300506032b656e032100");
  private static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");
  private static final byte[]    x448Prefix = Hex.decode("3042300506032b656f033900");
  private static final byte[]   Ed448Prefix = Hex.decode("3043300506032b6571033a00");

  private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

  private static final Map<String, KeyPairGenerator> KEYPAIR_GENERATORS = new HashMap<>();

  private KeyUtil() {
  }

  public static KeyStore getInKeyStore(String storeType) throws KeyStoreException {
    return getKeyStore(storeType, "BC");
  }

  public static KeyStore getOutKeyStore(String storeType) throws KeyStoreException {
    return getKeyStore(storeType, "SunJSSE");
  }

  private static KeyStore getKeyStore(String storeType, String pkcs12Provider) throws KeyStoreException {
    notBlank(storeType, "storeType");
    if (StringUtil.orEqualsIgnoreCase(storeType, "PKCS12", "PKCS#12")) {
      try {
        return KeyStore.getInstance(storeType, pkcs12Provider);
      } catch (KeyStoreException | NoSuchProviderException ex) {
        return KeyStore.getInstance(storeType);
      }
    } else {
      return KeyStore.getInstance(storeType);
    }
  }

  public static KeyPair generateRSAKeypair(int keysize, BigInteger publicExponent, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
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

  public static PrivateKeyInfo toPrivateKeyInfo(RSAPrivateCrtKey priv) throws IOException {
    /*
     * RSA private keys are BER-encoded according to PKCS #1’s RSAPrivateKey ASN.1 type.
     *
     * RSAPrivateKey ::= SEQUENCE {
     *   version           Version,
     *   modulus           INTEGER,  -- n
     *   publicExponent    INTEGER,  -- e
     *   privateExponent   INTEGER,  -- d
     *   prime1            INTEGER,  -- p
     *   prime2            INTEGER,  -- q
     *   exponent1         INTEGER,  -- d mod (p-1)
     *   exponent2         INTEGER,  -- d mod (q-1)
     *   coefficient       INTEGER,  -- (inverse of q) mod p
     *   otherPrimeInfos   OtherPrimeInfos OPTIONAL.
     * }
     */
    return new PrivateKeyInfo(ALGID_RSA,
        new org.bouncycastle.asn1.pkcs.RSAPrivateKey(priv.getModulus(),
            priv.getPublicExponent(), priv.getPrivateExponent(), priv.getPrimeP(), priv.getPrimeQ(),
            priv.getPrimeExponentP(), priv.getPrimeExponentQ(),  priv.getCrtCoefficient()));
  }

  public static KeyPair generateDSAKeypair(int plength, int qlength, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    DSAParameterSpec dsaParamSpec = DSAParameterCache.getDSAParameterSpec(plength, qlength, random);
    KeyPairGenerator kpGen = getKeyPairGenerator("DSA");
    synchronized (kpGen) {
      kpGen.initialize(dsaParamSpec, random);
      return kpGen.generateKeyPair();
    }
  }

  public static KeyPair generateDSAKeypair(DSAParameters dsaParams, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    DSAParameterSpec dsaParamSpec = new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
    return generateDSAKeypair(dsaParamSpec, random);
  }

  public static KeyPair generateDSAKeypair(DSAParameterSpec dsaParamSpec, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    KeyPairGenerator kpGen = getKeyPairGenerator("DSA");
    synchronized (kpGen) {
      kpGen.initialize(dsaParamSpec, random);
      return kpGen.generateKeyPair();
    }
  }

  public static DSAPublicKey generateDSAPublicKey(DSAPublicKeySpec keySpec)
      throws InvalidKeySpecException {
    notNull(keySpec, "keySpec");
    KeyFactory kf = getKeyFactory("DSA");
    synchronized (kf) {
      return (DSAPublicKey) kf.generatePublic(keySpec);
    }
  }

  public static KeyPair generateEdECKeypair(ASN1ObjectIdentifier curveId, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    String algorithm = EdECConstants.getName(notNull(curveId, "curveId"));
    KeyPairGenerator kpGen = getKeyPairGenerator(algorithm);
    synchronized (kpGen) {
      if (random != null) {
        kpGen.initialize(EdECConstants.getKeyBitSize(curveId), random);
      }
      return kpGen.generateKeyPair();
    }
  }

  public static KeyPair generateECKeypair(ASN1ObjectIdentifier curveId, SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    ECGenParameterSpec spec = new ECGenParameterSpec(notNull(curveId, "curveId").getId());
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
   * the converted private key against the corresponding public key.
   * @param key XDH private key
   * @return the corresponding EdDSA private key (dummy)
   * @throws InvalidKeySpecException
   *           If key is invalid.
   */
  public static PrivateKey convertXDHToDummyEdDSAPrivateKey(PrivateKey key)
      throws InvalidKeySpecException {
    if (key instanceof XDHKey) {
      PrivateKeyInfo xdhPki = PrivateKeyInfo.getInstance(key.getEncoded());
      String xdhAlgo = key.getAlgorithm();

      try {
        PrivateKeyInfo edPki;
        if (xdhAlgo.equalsIgnoreCase(EdECConstants.X25519)) {
          edPki = new PrivateKeyInfo(new AlgorithmIdentifier(EdECConstants.id_ED25519), xdhPki.parsePrivateKey());
        } else if (xdhAlgo.equalsIgnoreCase(EdECConstants.X448)) {
          byte[] x448Octets = ASN1OctetString.getInstance(xdhPki.parsePrivateKey()).getOctets();
          byte[] ed448Octets = new byte[57];
          System.arraycopy(x448Octets, 0, ed448Octets, 0, 56);

          edPki = new PrivateKeyInfo(new AlgorithmIdentifier(EdECConstants.id_ED448), new DEROctetString(ed448Octets));
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
      KeyFactory kf = KEY_FACTORIES.get(alg);
      if (kf != null) {
        return kf;
      }

      try {
        kf = KeyFactory.getInstance(alg, "BC");
      } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
        throw new InvalidKeySpecException("could not find KeyFactory for " + alg + ": " + ex.getMessage());
      }
      KEY_FACTORIES.put(alg, kf);
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
      KeyPairGenerator kg = KEYPAIR_GENERATORS.get(alg);
      if (kg != null) {
        return kg;
      }

      kg = KeyPairGenerator.getInstance(alg, "BC");
      KEYPAIR_GENERATORS.put(alg, kg);
      return kg;
    }
  } // method getKeyPairGenerator

  public static PrivateKey generatePrivateKey(PrivateKeyInfo pkInfo)
      throws InvalidKeySpecException {
    notNull(pkInfo, "pkInfo");

    PKCS8EncodedKeySpec keyspec;
    try {
      keyspec = new PKCS8EncodedKeySpec(pkInfo.getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
    ASN1ObjectIdentifier oid = pkInfo.getPrivateKeyAlgorithm().getAlgorithm();

    String algorithm;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)) {
      algorithm = "RSA";
    } else if (X9ObjectIdentifiers.id_dsa.equals(oid)) {
      algorithm = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid)) {
      algorithm = "EC";
    } else {
      algorithm = EdECConstants.getName(oid);
    }

    if (algorithm == null) {
      throw new InvalidKeySpecException("unsupported key algorithm: " + oid);
    }

    KeyFactory kf = getKeyFactory(algorithm);
    synchronized (kf) {
      return kf.generatePrivate(keyspec);
    }
  } // method generatePublicKey

  public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
      throws InvalidKeySpecException {
    notNull(pkInfo, "pkInfo");

    X509EncodedKeySpec keyspec;
    try {
      keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
    ASN1ObjectIdentifier oid = pkInfo.getAlgorithm().getAlgorithm();

    String algorithm;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)) {
      algorithm = "RSA";
    } else if (X9ObjectIdentifiers.id_dsa.equals(oid)) {
      algorithm = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid)) {
      algorithm = "EC";
    } else {
      algorithm = EdECConstants.getName(oid);
    }

    if (algorithm == null) {
      throw new InvalidKeySpecException("unsupported key algorithm: " + oid);
    }

    KeyFactory kf = getKeyFactory(algorithm);
    synchronized (kf) {
      return kf.generatePublic(keyspec);
    }
  } // method generatePublicKey

  public static RSAPublicKey generateRSAPublicKey(RSAPublicKeySpec keySpec)
      throws InvalidKeySpecException {
    notNull(keySpec, "keySpec");
    KeyFactory kf = getKeyFactory("RSA");
    synchronized (kf) {
      return (RSAPublicKey) kf.generatePublic(keySpec);
    }
  }

  public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
      throws InvalidKeyException {
    notNull(key, "key");

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
    notNull(key, "key");

    if (key instanceof RSAPublicKey) {
      RSAPublicKey rsaKey = (RSAPublicKey) key;
      return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
    } else if (key instanceof ECPublicKey) {
      return ECUtil.generatePublicKeyParameter(key);
    } else if (key instanceof DSAPublicKey) {
      return DSAUtil.generatePublicKeyParameter(key);
    } else if (key instanceof XDHKey || key instanceof EdDSAKey) {
      byte[] encoded = key.getEncoded();
      String algorithm = key.getAlgorithm().toUpperCase();
      switch (algorithm) {
        case EdECConstants.X25519:
          return new X25519PublicKeyParameters(encoded, encoded.length - 32);
        case EdECConstants.ED25519:
          return new Ed25519PublicKeyParameters(encoded, encoded.length - 32);
        case EdECConstants.X448:
          return new X448PublicKeyParameters(encoded, encoded.length - 56);
        case EdECConstants.ED448:
          return new Ed448PublicKeyParameters(encoded, encoded.length - 57);
        default:
          throw new InvalidKeyException("unknown Edwards key " + algorithm);
      }
    } else {
      throw new InvalidKeyException("unknown key " + key.getClass().getName());
    }
  } // method generatePublicKeyParameter

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
      throws InvalidKeyException {
    notNull(publicKey, "publicKey");

    if (publicKey instanceof DSAPublicKey) {
      DSAPublicKey dsaPubKey = (DSAPublicKey) publicKey;
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new ASN1Integer(dsaPubKey.getParams().getP()));
      vec.add(new ASN1Integer(dsaPubKey.getParams().getQ()));
      vec.add(new ASN1Integer(dsaPubKey.getParams().getG()));
      ASN1Sequence dssParams = new DERSequence(vec);

      try {
        return new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dssParams), new ASN1Integer(dsaPubKey.getY()));
      } catch (IOException ex) {
        throw new InvalidKeyException(ex.getMessage(), ex);
      }
    } else if (publicKey instanceof RSAPublicKey) {
      RSAPublicKey rsaPubKey = (RSAPublicKey) publicKey;
      try {
        return new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));
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

      AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid);
      return new SubjectPublicKeyInfo(algId, pubKey);
    } else if (publicKey instanceof XDHKey || publicKey instanceof EdDSAKey) {
      String algorithm = publicKey.getAlgorithm().toUpperCase();
      byte[] encoded = publicKey.getEncoded();

      int keysize;
      byte[] prefix;
      ASN1ObjectIdentifier algOid;
      switch (algorithm) {
        case EdECConstants.ED25519:
          algOid = EdECConstants.id_ED25519;
          keysize = 32;
          prefix = Ed25519Prefix;
          break;
        case EdECConstants.X25519:
          algOid = EdECConstants.id_X25519;
          keysize = 32;
          prefix = x25519Prefix;
          break;
        case EdECConstants.ED448:
          algOid = EdECConstants.id_ED448;
          keysize = 57;
          prefix = Ed448Prefix;
          break;
        case EdECConstants.X448:
          algOid = EdECConstants.id_X448;
          keysize = 56;
          prefix = x448Prefix;
          break;
        default:
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

  public static ECPublicKey createECPublicKey(byte[] encodedAlgorithmIdParameters, byte[] encodedPoint)
      throws InvalidKeySpecException {
    notNull(encodedAlgorithmIdParameters, "encodedAlgorithmIdParameters");
    notNull(encodedPoint, "encodedPoint");

    ASN1Encodable algParams =(encodedAlgorithmIdParameters[0] == 6)
        ? ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters)
        : X962Parameters.getInstance(encodedAlgorithmIdParameters);

    AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, algParams);

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

  public static ASN1ObjectIdentifier detectCurveOid(ECParameterSpec paramSpec) {
    return ECUtil.getNamedCurveOid(EC5Util.convertSpec(paramSpec));
  }

  public static byte[] getUncompressedEncodedECPoint(ECPoint point, int orderBitLength) {
    int orderByteLength = (orderBitLength + 7) / 8;
    byte[] keyData = new byte[1 + orderByteLength * 2];
    keyData[0] = 4;
    unsignedByteArrayCopy(keyData, 1, orderByteLength, point.getAffineX());
    unsignedByteArrayCopy(keyData, 1 + orderByteLength, orderByteLength, point.getAffineY());
    return keyData;
  } // method getUncompressedEncodedECPoint

  /**
   * Write the passed in value as an unsigned byte array to the {@code dest} from offset
   * {@code destPos}.
   *
   * @param value value to be converted.
   * @param destPos destination
   */
  private static void unsignedByteArrayCopy(byte[] dest, int destPos, int length, BigInteger value) {
    byte[] bytes = value.toByteArray();
    if (bytes.length == length) {
      System.arraycopy(bytes, 0, dest, destPos, length);
    } else {
      int start = bytes[0] == 0 ? 1 : 0;
      int count = bytes.length - start;

      if (count > length) {
        throw new IllegalArgumentException("value cannot be expressed in " + length + " bytes");
      }

      System.arraycopy(bytes, start, dest, destPos + length - count, count);
    }
  } // method unsignedByteArrayCopy

}
