// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.encap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.composite.CompositeKemSuite;
import org.xipki.security.composite.CompositeKemUtil;
import org.xipki.security.composite.CompositeMLKEMPrivateKey;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SecretKeyWithAlias;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;

/**
 * KEMUtil.
 *
 * @author Lijun Liao (xipki)
 */
public class KEMUtil {

  private static final String id_ml_kem_512 = "2.16.840.1.101.3.4.4.1";
  private static final String id_ml_kem_768 = "2.16.840.1.101.3.4.4.2";
  private static final String id_ml_kem_1024 = "2.16.840.1.101.3.4.4.3";

  // macKey          = derive(masterKey, spki)
  // encapKey        = encapsulateKey(spki)
  // encryptedMacKey = enc_aesGcm(encapKey.secret, macKey)
  // result          = (encapKey.encapsulation, encryptedMacKey)
  public static KemEncapKey generateKemEncapKey(
      SubjectPublicKeyInfo spki, SecretKeyWithAlias masterKey, SecureRandom rnd)
      throws XiSecurityException {
    byte[] rawPkData = Asn1Util.getPublicKeyData(spki);

    // derive the MAC key
    byte[] macKey = hmacDerive(masterKey.secretKey(), 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);
    return new KemEncapKey(masterKey.alias(), kemEncryptSecret(spki, macKey, rnd));
  }

  public static KemEncapsulation kemEncryptSecret(
      SubjectPublicKeyInfo spki, byte[] secret, SecureRandom rnd) throws XiSecurityException {
    AlgorithmIdentifier algId = spki.getAlgorithm();
    ASN1ObjectIdentifier algOid = algId.getAlgorithm();

    // Encapsulate a random key
    byte alg;
    SecretWithEncap skEncap;
    if (OIDs.Algo.id_ml_kem_512.equals(algOid) || OIDs.Algo.id_ml_kem_768.equals(algOid) ||
        OIDs.Algo.id_ml_kem_1024.equals(algOid)) {
      alg = KemEncapsulation.ALG_KMAC_MLKEM_HMAC;

      MLKEMGenerator gen = new MLKEMGenerator(rnd);
      MLKEMParameters variant = getMLKEMVariant(spki.getAlgorithm());
      MLKEMPublicKeyParameters pkParams =
          new MLKEMPublicKeyParameters(variant, spki.getPublicKeyData().getOctets());

      skEncap = new SecretWithEncap(gen.generateEncapsulated(pkParams));
    } else {
      CompositeKemSuite suite = CompositeKemSuite.getAlgoSuite(algId);
      if (suite == null) {
        throw new IllegalArgumentException("The given public key (spki) " +
            "is neither an MLKEM nor a composite MLKEM key.");
      }

      alg = KemEncapsulation.ALG_KMAC_COMPOSITE_MLKEM_HMAC;
      skEncap = CompositeKemUtil.encap(suite, Asn1Util.getPublicKeyData(spki), rnd);
    }

    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(skEncap.secret(), "AES"),
          // skEncap.getSecret() is always fresh, so we used here constant IV.
          new GCMParameterSpec(128, new byte[12]));
      byte[] encryptedSecret = cipher.doFinal(secret);

      return new KemEncapsulation(alg, skEncap.encap(), encryptedSecret);
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException(e);
    }
  }

  public static SecretWithEncapsulation encapsulateKey(
      KeySpec keySpec, byte[] publicKeyData, SecureRandom rnd) {
    MLKEMPublicKeyParameters pkParams = new MLKEMPublicKeyParameters(
        getMLKEMParameters(keySpec), publicKeyData);
    MLKEMGenerator gen = new MLKEMGenerator(rnd);
    return gen.generateEncapsulated(pkParams);
  }

  public static MLKEMParameters getMLKEMParameters(KeySpec keySpec) {
    switch (keySpec) {
      case MLKEM512:
        return MLKEMParameters.ml_kem_512;
      case MLKEM768:
        return MLKEMParameters.ml_kem_768;
      case MLKEM1024:
        return MLKEMParameters.ml_kem_1024;
      default:
        throw new IllegalArgumentException("invalid keySpec " + keySpec);
    }
  }

  // returns the decapsulated secret. pkValue is needed for the composite KEM.
  public static byte[] mlkemDecryptSecret(
      PrivateKey privateKey, KemEncapsulation kemEncapsulation) throws XiSecurityException {
    PrivateKeyInfo skInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
    AlgorithmIdentifier algId = skInfo.getPrivateKeyAlgorithm();
    ASN1ObjectIdentifier algOid = algId.getAlgorithm();

    if (OIDs.Algo.id_ml_kem_512.equals(algOid) || OIDs.Algo.id_ml_kem_768.equals(algOid) ||
        OIDs.Algo.id_ml_kem_1024.equals(algOid)) {
      MLKEMPrivateKeyParameters params = toPrivateParameters(skInfo);
      byte[] decapKey = new MLKEMExtractor(params).extractSecret(kemEncapsulation.encapKey());
      return doKemDecryptSecret(decapKey, kemEncapsulation);
    } else {
      throw new IllegalArgumentException("The given private key is not an MLKEM key.");
    }
  }

  private static MLKEMPrivateKeyParameters toPrivateParameters(PrivateKeyInfo skInfo) {
    MLKEMParameters variant = getMLKEMVariant(skInfo.getPrivateKeyAlgorithm());
    byte[] skData = skInfo.getPrivateKey().getOctets();
    byte tag = skData[0];

    if (tag == (BERTags.CONSTRUCTED | BERTags.SEQUENCE))  {
      ASN1Sequence seq = ASN1Sequence.getInstance(skData);
      byte[] expanded = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();
      return new MLKEMPrivateKeyParameters(variant, expanded);
    } else if (tag == BERTags.OCTET_STRING) {
      byte[] expanded = ASN1OctetString.getInstance(skData).getOctets();
      return new MLKEMPrivateKeyParameters(variant, expanded);
    } else if (tag == (byte) (BERTags.CONTEXT_SPECIFIC | 0)) {
      // seed [0] IMPLICIT OCTET STRING
      ASN1Primitive asn1Obj = Asn1Util.getImplicitBaseObject(
                  ASN1TaggedObject.getInstance(skData), BERTags.OCTET_STRING)
                  .toASN1Primitive();
      byte[] seed = ((ASN1OctetString) asn1Obj).getOctets();
      return new MLKEMPrivateKeyParameters(variant, seed);
    } else {
      throw new IllegalArgumentException("invalid tag " + (0xFF & tag));
    }
  }

  private static MLKEMParameters getMLKEMVariant(AlgorithmIdentifier algId) {
    String oid = algId.getAlgorithm().getId();
    if (oid.equals(id_ml_kem_512)) {
      return MLKEMParameters.ml_kem_512;
    } else if (oid.equals(id_ml_kem_768)) {
      return MLKEMParameters.ml_kem_768;
    } else if (oid.equals(id_ml_kem_1024)) {
      return MLKEMParameters.ml_kem_1024;
    } else {
      throw new IllegalArgumentException("invalid MLKEM algId " + oid);
    }
  }

  public static byte[] decapsulateKey(KeySpec keySpec, byte[] skValue, byte[] encapKey) {
    MLKEMPrivateKeyParameters dkObj =
        new MLKEMPrivateKeyParameters(getMLKEMParameters(keySpec), skValue);
    return new MLKEMExtractor(dkObj).extractSecret(encapKey);
  }

  public static byte[] compositeMlKemDecryptSecret(
      PrivateKey privateKey, byte[] publicKeyData, KemEncapsulation kemEncapsulation)
      throws XiSecurityException {
    byte[] sk;
    CompositeKemSuite suite;

    if (privateKey instanceof CompositeMLKEMPrivateKey) {
      suite = ((CompositeMLKEMPrivateKey) privateKey).suite();
      sk = ((CompositeMLKEMPrivateKey) privateKey).keyValue();
    } else {
      PrivateKeyInfo skInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
      suite = CompositeKemSuite.getAlgoSuite(skInfo.getPrivateKeyAlgorithm());
      if (suite == null) {
        throw new IllegalArgumentException("The given public key (spki) " +
            "is not an MLKEM or composite MLKEM key.");
      }
      sk = skInfo.getPrivateKey().getOctets();
    }

    byte[] decapKey = CompositeKemUtil.decap(suite, sk, publicKeyData, kemEncapsulation.encapKey());
    return doKemDecryptSecret(decapKey, kemEncapsulation);
  }

  public static byte[] doKemDecryptSecret(byte[] decapKey, KemEncapsulation kemEncapsulation)
      throws XiSecurityException {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decapKey, "AES"),
          new GCMParameterSpec(128, new byte[12]));
    return cipher.doFinal(kemEncapsulation.encryptedSecret());
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException(e);
    }
  }

  public static byte[] hmacDerive(SecretKey ikm, int keyByteSize, byte[] info, byte[] data) {
    return hmacDerive(ikm.getEncoded(), keyByteSize, info, data);
  }

  public static byte[] hmacDerive(byte[] ikm, int keyByteSize, byte[] info, byte[] data) {
    return KeyUtil.hkdf(HashAlgo.SHA256, data, ikm, info, keyByteSize);
  }

}
