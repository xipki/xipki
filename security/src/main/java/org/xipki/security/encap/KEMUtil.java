// Copyright (c) 2013-2025 xipki. All rights reserved.
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
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.xipki.security.OIDs;
import org.xipki.security.bc.compositekem.CompositeMLKEMPrivateKey;
import org.xipki.security.composite.CompositeKemSuite;
import org.xipki.security.composite.CompositeKemUtil;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.SecretKeyWithAlias;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @author Lijun Liao (xipki)
 */
public class KEMUtil {

  public static MLKEMParameters getMLKEMVariant(AlgorithmIdentifier algId) {
    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (oid.equals(OIDs.Algo.id_ml_kem_512)) {
      return MLKEMParameters.ml_kem_512;
    } else if (oid.equals(OIDs.Algo.id_ml_kem_768)) {
      return MLKEMParameters.ml_kem_768;
    } else if (oid.equals(OIDs.Algo.id_ml_kem_1024)) {
      return MLKEMParameters.ml_kem_1024;
    } else {
      throw new IllegalArgumentException("invalid MLKEM algId " + oid.getId());
    }
  }

  public static MLKEMPublicKeyParameters toPublicParameters(
      SubjectPublicKeyInfo pkInfo) {
    MLKEMParameters variant = getMLKEMVariant(pkInfo.getAlgorithm());
    return new MLKEMPublicKeyParameters(variant,
            pkInfo.getPublicKeyData().getOctets());
  }

  public static MLKEMPublicKeyParameters toPublicParameters(
      PublicKey publicKey) {
    SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(
        publicKey.getEncoded());
    return toPublicParameters(pkInfo);
  }

  public static MLKEMPrivateKeyParameters toPrivateParameters(
      PrivateKeyInfo skInfo) {
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
    } else if (tag == 0x0) {
      ASN1Primitive asn1Obj = ASN1TaggedObject.getInstance(skData)
          .getBaseUniversal(false, BERTags.OCTET_STRING);
      byte[] seed = ((ASN1OctetString) asn1Obj).getOctets();
      return new MLKEMPrivateKeyParameters(variant, seed);
    } else {
      throw new IllegalArgumentException("invalid tag " + (0xFF & tag));
    }
  }

  public static MLKEMPrivateKeyParameters toPrivateParameters(
      PrivateKey privateKey) {
    PrivateKeyInfo skInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
    return toPrivateParameters(skInfo);
  }

  // macKey          = derive(masterKey, spki)
  // encapKey        = encapsulateKey(spki)
  // encryptedMacKey = enc_aesGcm(encapKey.secret, macKey)
  // result          = (encapKey.encapsulation, encryptedMacKey)
  public static KemEncapKey generateKemEncapKey(
      SubjectPublicKeyInfo spki, SecretKeyWithAlias masterKey, SecureRandom rnd)
      throws XiSecurityException {
    byte[] rawPkData = spki.getPublicKeyData().getOctets();

    // derive the MAC key
    byte[] macKey = kmacDerive(masterKey.getSecretKey(), 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);
    return new KemEncapKey(masterKey.getAlias(),
        kemEncryptSecret(spki, macKey, rnd));
  }

  public static KemEncapsulation kemEncryptSecret(
      SubjectPublicKeyInfo spki, byte[] secret, SecureRandom rnd)
      throws XiSecurityException {
    AlgorithmIdentifier algId = spki.getAlgorithm();
    ASN1ObjectIdentifier algOid = algId.getAlgorithm();

    // Encapsulate a random key
    byte alg;
    SecretWithEncap skEncap;
    if (OIDs.Algo.id_ml_kem_512.equals(algOid) ||
        OIDs.Algo.id_ml_kem_768.equals(algOid) ||
        OIDs.Algo.id_ml_kem_1024.equals(algOid)) {
      alg = KemEncapsulation.ALG_KMAC_MLKEM_HMAC;
      MLKEMGenerator gen = new MLKEMGenerator(rnd);
      MLKEMPublicKeyParameters pkParams = toPublicParameters(spki);
      skEncap = new SecretWithEncap(gen.generateEncapsulated(pkParams));
    } else {
      CompositeKemSuite suite = CompositeKemSuite.getAlgoSuite(algId);
      if (suite == null) {
        throw new IllegalArgumentException("The given public key (spki) " +
            "is neither an MLKEM nor a composite MLKEM key.");
      }

      alg = KemEncapsulation.ALG_KMAC_COMPOSITE_MLKEM_HMAC;
      skEncap = CompositeKemUtil.encap(suite,
                  spki.getPublicKeyData().getOctets(), rnd);
    }

    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE,
          new SecretKeySpec(skEncap.getSecret(), "AES"),
          // skEncap.getSecret() is always fresh, so we used here constant IV.
          new GCMParameterSpec(128, new byte[12]));
      byte[] encryptedSecret = cipher.doFinal(secret);

      return new KemEncapsulation(alg, skEncap.getEncap(), encryptedSecret);
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException(e);
    }
  }

  // returns the decapsulated secret. pkValue is needed for the composite KEM.
  public static byte[] mlkemDecryptSecret(
      PrivateKey privateKey, KemEncapsulation kemEncapsulation)
      throws XiSecurityException {
    PrivateKeyInfo skInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
    AlgorithmIdentifier algId = skInfo.getPrivateKeyAlgorithm();
    ASN1ObjectIdentifier algOid = algId.getAlgorithm();

    if (OIDs.Algo.id_ml_kem_512.equals(algOid) ||
        OIDs.Algo.id_ml_kem_768.equals(algOid) ||
        OIDs.Algo.id_ml_kem_1024.equals(algOid)) {
      MLKEMPrivateKeyParameters params = KEMUtil.toPrivateParameters(skInfo);
      MLKEMExtractor extractor = new MLKEMExtractor(params);
      byte[] decapKey = extractor.extractSecret(kemEncapsulation.getEncapKey());
      return doKemDecryptSecret(decapKey, kemEncapsulation);
    } else {
      throw new IllegalArgumentException(
            "The given private key is not an MLKEM key.");
    }
  }

  public static byte[] compositeMlKemDecryptSecret(
      PrivateKey privateKey, byte[] publicKeyData,
      KemEncapsulation kemEncapsulation)
      throws XiSecurityException {
    byte[] sk;
    CompositeKemSuite suite;

    if (privateKey instanceof CompositeMLKEMPrivateKey) {
      suite = ((CompositeMLKEMPrivateKey) privateKey).getSuite();
      sk = ((CompositeMLKEMPrivateKey) privateKey).getKeyValue();
    } else {
      PrivateKeyInfo skInfo =
          PrivateKeyInfo.getInstance(privateKey.getEncoded());
      suite = CompositeKemSuite.getAlgoSuite(
          skInfo.getPrivateKeyAlgorithm());
      if (suite == null) {
        throw new IllegalArgumentException("The given public key (spki) " +
            "is not an MLKEM or composite MLKEM key.");
      }
      sk = skInfo.getPrivateKey().getOctets();
    }

    byte[] decapKey = CompositeKemUtil.decap(suite, sk, publicKeyData,
        kemEncapsulation.getEncapKey());
    return doKemDecryptSecret(decapKey, kemEncapsulation);
  }

  private static byte[] doKemDecryptSecret(
      byte[] decapKey, KemEncapsulation kemEncapsulation)
      throws XiSecurityException {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE,
          new SecretKeySpec(decapKey, "AES"),
          new GCMParameterSpec(128, new byte[12]));
    return cipher.doFinal(kemEncapsulation.getEncryptedSecret());
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException(e);
    }
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

}
