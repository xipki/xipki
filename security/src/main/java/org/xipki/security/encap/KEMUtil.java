// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.encap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.bridge.BridgeKEMUtil;
import org.xipki.security.bridge.BridgeMlkemVariant;
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
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class KEMUtil {

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
      skEncap = new SecretWithEncap(BridgeKEMUtil.encapsulateKey(spki, rnd));
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
    BridgeMlkemVariant variant = toBridgeMlkemVariant(keySpec);
    return BridgeKEMUtil.encapsulateKey(variant, publicKeyData, rnd);
  }

  public static BridgeMlkemVariant toBridgeMlkemVariant(KeySpec keySpec) {
    switch (keySpec) {
      case MLKEM512:
        return BridgeMlkemVariant.mlkem512;
      case MLKEM768:
        return BridgeMlkemVariant.mlkem768;
      case MLKEM1024:
        return BridgeMlkemVariant.mlkem1024;
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
      byte[] decapKey = BridgeKEMUtil.decapsulateKey(skInfo, kemEncapsulation.encapKey());
      return doKemDecryptSecret(decapKey, kemEncapsulation);
    } else {
      throw new IllegalArgumentException("The given private key is not an MLKEM key.");
    }
  }

  public static byte[] decapsulateKey(KeySpec keySpec, byte[] skValue, byte[] encapKey) {
    BridgeMlkemVariant variant = toBridgeMlkemVariant(keySpec);
    return BridgeKEMUtil.decapsulateKey(variant, skValue, encapKey);
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
