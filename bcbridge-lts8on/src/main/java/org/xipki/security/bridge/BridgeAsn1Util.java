// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;

import java.text.ParseException;
import java.time.Instant;

/**
 * Bridge Asn1 Util.
 *
 * @author Lijun Liao (xipki)
 */
public class BridgeAsn1Util {

  private static final int cmp2021 = 3;

  public static boolean supportsCmpVersion(int version) {
    return version <= cmp2021;
  }

  public static ASN1Encodable getBaseObject(ASN1TaggedObject taggedObject) {
    return taggedObject.getBaseObject();
  }

  public static ASN1Encodable getImplicitBaseObject(
      ASN1TaggedObject taggedObject, int baseObjTagNo) {
    return taggedObject.getBaseUniversal(false, baseObjTagNo);
  }

  public static String getTextAt(PKIFreeText pkiFreeText, int index) {
    return pkiFreeText.getStringAtUTF8(index).getString();
  }

  public static String getSourceDataUri(BiometricData biometricData) {
    ASN1IA5String ia5 = biometricData.getSourceDataUriIA5();
    return (ia5 == null) ? null : ia5.getString();
  }

  public static byte[] getKeyIdentifier(AuthorityKeyIdentifier aki) {
    return aki.getKeyIdentifierOctets();
  }

  public static byte[] getPublicKeyData(SubjectPublicKeyInfo ski) {
    return ski.getPublicKeyData().getOctets();
  }

  public static byte[] getECPublicKeyData(
      ECPrivateKey ecPrivateKey, PrivateKeyInfo privateKeyInfo) {
    if (ecPrivateKey.getPublicKey() != null) {
      return ecPrivateKey.getPublicKey().getOctets();
    }

    if (privateKeyInfo.getPublicKeyData() != null) {
      return privateKeyInfo.getPublicKeyData().getOctets();
    }

    return null;
  }

  public static String getBMPString(ASN1Encodable str) {
    return ASN1BMPString.getInstance(str).getString();
  }

  public static String getIA5String(ASN1Encodable str) {
    return ASN1IA5String.getInstance(str).getString();
  }

  public static String getPrintableString(ASN1Encodable str) {
    return ASN1PrintableString.getInstance(str).getString();
  }

  public static String getUTF8String(ASN1Encodable str) {
    return ASN1UTF8String.getInstance(str).getString();
  }

  public static byte[] getBitStringOctets(Object obj) {
    return ASN1BitString.getInstance(obj).getOctets();
  }

  public static byte[] getOctetStringOctets(Object obj) {
    return ASN1OctetString.getInstance(obj).getOctets();
  }

  public static Instant getUTCTime(Object obj) throws ParseException {
    return ASN1UTCTime.getInstance(obj).getDate().toInstant();
  }

  public static Instant getGeneralizedTime(Object obj) throws ParseException {
    return ASN1GeneralizedTime.getInstance(obj).getDate().toInstant();
  }

  public static ASN1BitString toASN1BitString(Object obj) {
    return ASN1BitString.getInstance(obj);
  }

  public static ASN1OctetString toASN1OctetString(Object obj) {
    return ASN1OctetString.getInstance(obj);
  }

  public static byte[] getSignature(Certificate cert) {
    return cert.getSignature().getOctets();
  }

  public static byte[] getEncSymmKey(EncryptedValue encryptedValue) {
    return encryptedValue.getEncSymmKey().getOctets();
  }

  public static byte[] getEncValue(EncryptedValue encryptedValue) {
    return encryptedValue.getEncValue().getOctets();
  }

  public static BiometricData buildBiometricData(
        TypeOfBiometricData type, AlgorithmIdentifier hashAlgId,
        byte[] biometricDataHash, String sourceDataUri) {
    return new BiometricData(type, hashAlgId, new DEROctetString(biometricDataHash),
      sourceDataUri == null ? null : new DERIA5String(sourceDataUri));
  }

  public static EncryptedValue buildEncryptedValue(
      AlgorithmIdentifier intendedAlg, AlgorithmIdentifier symmAlg, byte[] encSymmKey,
      AlgorithmIdentifier keyAlg, byte[] valueHint, byte[] encValue) {
    return new EncryptedValue(intendedAlg, symmAlg,
        (encSymmKey == null ? null : new DERBitString(encSymmKey)), keyAlg,
        (valueHint == null ? null : new DEROctetString(valueHint)), new DERBitString(encValue));
  }

}
