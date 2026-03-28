// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.OperatorException;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.exception.XiSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

/**
 * Crmf Util.
 *
 * @author Lijun Liao (xipki)
 */
public class CrmfUtil {

  private static final AlgorithmIdentifier ALG_ID =
      new AlgorithmIdentifier(OIDs.Xipki.id_alg_ECIES_hkdfsha256_aes256_gcm);

  public static byte[] wrapCrmfContentEncryptionKey(
      byte[] keyToWrap, ECPublicKey publicKey, SecureRandom rnd)
      throws OperatorException {
    try {
      byte[] gcmIv = new byte[12];
      rnd.nextBytes(gcmIv);
      WeierstraussCurveEnum curveEnum = curveOf(publicKey.getParams());
      byte[][] ephemeralKeyPair = curveEnum.generateKeyPair(rnd);
      byte[] ephemeralSk        = ephemeralKeyPair[0];
      byte[] ephemeralPublicKey = ephemeralKeyPair[1];

      // ECDH
      ECPoint peerECPoint = curveEnum.decodePoint(
          Asn1Util.getPublicKeyData(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())));

      byte[] aesKey = ecdhHkdf(curveEnum, new BigInteger(1, ephemeralSk),
          peerECPoint, ephemeralPublicKey, 32);
      Cipher gcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
      gcmCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
          new GCMParameterSpec(128, gcmIv));
      byte[] EM = gcmCipher.doFinal(keyToWrap);

      // convert the result to ASN.1 format
      ASN1EncodableVector v = new ASN1EncodableVector(3);
      // ephemeralPublicKey ECPoint
      v.add(new DEROctetString(ephemeralPublicKey));
      // IV
      v.add(new DEROctetString(gcmIv));
      // encrypted message
      v.add(new DEROctetString(EM));
      return new DERSequence(v).getEncoded();
    } catch (Exception ex) {
      throw new OperatorException("error while generateWrappedKey", ex);
    }
  } // method wrapCrmfSymmetricKey

  public static byte[] unwrapCrmfContentEncryptionKey(
      ECPrivateKey privateKey, AlgorithmIdentifier keyAlgId, EncryptedValue ev)
      throws XiSecurityException {
    ASN1ObjectIdentifier keyOid = keyAlgId.getAlgorithm();
    if (!keyAlgId.getAlgorithm().equals(OIDs.Xipki.id_alg_ECIES_hkdfsha256_aes256_gcm)) {
      throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
    }

    byte[] ECIESCiphertextValue = Asn1Util.getEncSymmKey(ev);
    return unwrapCrmfSymmetricKey(ECIESCiphertextValue, privateKey);
  }

  private static byte[] unwrapCrmfSymmetricKey(byte[] encryptedInfo, ECPrivateKey decKey)
      throws XiSecurityException {
    try {
      ASN1Sequence seq = ASN1Sequence.getInstance(encryptedInfo);
      byte[] ephemeralPublicKey = Asn1Util.getOctetStringOctets(seq.getObjectAt(0));
      byte[] gcmIv = Asn1Util.getOctetStringOctets(seq.getObjectAt(1));
      byte[] EM = Asn1Util.getOctetStringOctets(seq.getObjectAt(2));

      WeierstraussCurveEnum curveEnum = curveOf(decKey.getParams());
      ECPoint ephemeralPoint = curveEnum.decodePoint(ephemeralPublicKey);

      byte[] aesKey = ecdhHkdf(curveEnum, decKey.getS(), ephemeralPoint, ephemeralPublicKey, 32);

      Cipher gcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
      gcmCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
          new GCMParameterSpec(128, gcmIv));
      return gcmCipher.doFinal(EM);
    } catch (GeneralSecurityException | OperatorException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // unwrapCrmfSymmetricKey2

  public static AlgorithmIdentifier buildCrmfAlgId() {
    return ALG_ID;
  }

  static WeierstraussCurveEnum curveOf(ECParameterSpec ecParameterSpec) throws OperatorException {
    byte[] ecParams = Functions.getEcParams(ecParameterSpec.getOrder(),
              ecParameterSpec.getGenerator().getAffineX());
    WeierstraussCurveEnum curveEnum = null;
    if (ecParams != null) {
      curveEnum = WeierstraussCurveEnum.ofEcParams(ecParams);
    }

    if (curveEnum == null) {
      throw new OperatorException("invalid publicKey: unknown curve");
    }
    return curveEnum;
  }

  private static byte[] ecdhHkdf(
      WeierstraussCurveEnum curveEnum, BigInteger sk, ECPoint peerECPoint,
      byte[] ephemeralECPoint, int aesKeyByteSize) {
    byte[] encodedECDHPoint = peerECPoint.multiply(sk).normalize().getEncoded(false);
    byte[] ecdhRes = Arrays.copyOfRange(encodedECDHPoint, 1, 1 + curveEnum.getFieldByteSize());

    return KeyUtil.hkdf(HashAlgo.SHA256, ephemeralECPoint, ecdhRes,
        new byte[]{'C', 'R', 'M', 'F'}, aesKeyByteSize);
  }

}
