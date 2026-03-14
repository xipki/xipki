// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
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
import org.xipki.security.bridge.BridgeAsn1Util;

import java.text.ParseException;
import java.time.Instant;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Util {

  public static boolean supportsCmpVersion(int version) {
    return BridgeAsn1Util.supportsCmpVersion(version);
  }

  public static ASN1Encodable getBaseObject(ASN1TaggedObject taggedObject) {
    return BridgeAsn1Util.getBaseObject(taggedObject);
  }

  public static ASN1Encodable getImplicitBaseObject(
      ASN1TaggedObject taggedObject, int baseObjTagNo) {
    return BridgeAsn1Util.getImplicitBaseObject(taggedObject, baseObjTagNo);
  }

  public static String getTextAt(PKIFreeText pkiFreeText, int index) {
    return BridgeAsn1Util.getTextAt(pkiFreeText, index);
  }

  public static String getSourceDataUri(BiometricData biometricData) {
    return BridgeAsn1Util.getSourceDataUri(biometricData);
  }

  public static byte[] getKeyIdentifier(AuthorityKeyIdentifier aki) {
    return BridgeAsn1Util.getKeyIdentifier(aki);
  }

  public static byte[] getPublicKeyData(SubjectPublicKeyInfo ski) {
    return BridgeAsn1Util.getPublicKeyData(ski);
  }

  public static byte[] getECPublicKeyData(
      ECPrivateKey ecPrivateKey, PrivateKeyInfo privateKeyInfo) {
    return BridgeAsn1Util.getECPublicKeyData(ecPrivateKey, privateKeyInfo);
  }

  public static String getBMPString(ASN1Encodable str) {
    return BridgeAsn1Util.getBMPString(str);
  }

  public static String getIA5String(ASN1Encodable str) {
    return BridgeAsn1Util.getIA5String(str);
  }

  public static String getPrintableString(ASN1Encodable str) {
    return BridgeAsn1Util.getPrintableString(str);
  }

  public static String getUTF8String(ASN1Encodable str) {
    return BridgeAsn1Util.getUTF8String(str);
  }

  public static byte[] getBitStringOctets(Object obj) {
    return BridgeAsn1Util.getBitStringOctets(obj);
  }

  public static byte[] getOctetStringOctets(Object obj) {
    return BridgeAsn1Util.getOctetStringOctets(obj);
  }

  public static Instant getUTCTime(Object obj) throws ParseException {
    return BridgeAsn1Util.getUTCTime(obj);
  }

  public static Instant getGeneralizedTime(Object obj) throws ParseException {
    return BridgeAsn1Util.getGeneralizedTime(obj);
  }

  public static ASN1BitString toASN1BitString(Object obj) {
    return BridgeAsn1Util.toASN1BitString(obj);
  }

  public static ASN1OctetString toASN1OctetString(Object obj) {
    return BridgeAsn1Util.toASN1OctetString(obj);
  }

  public static byte[] getSignature(Certificate cert) {
    return BridgeAsn1Util.getSignature(cert);
  }

  public static byte[] getEncSymmKey(EncryptedValue encryptedValue) {
    return BridgeAsn1Util.getEncSymmKey(encryptedValue);
  }

  public static byte[] getEncValue(EncryptedValue encryptedValue) {
    return BridgeAsn1Util.getEncValue(encryptedValue);
  }

  public static BiometricData buildBiometricData(
      TypeOfBiometricData type, AlgorithmIdentifier hashAlgId,
      byte[] biometricDataHash, String sourceDataUri) {
    return BridgeAsn1Util.buildBiometricData(type, hashAlgId, biometricDataHash, sourceDataUri);
  }

  public static EncryptedValue buildEncryptedValue(
      AlgorithmIdentifier intendedAlg, AlgorithmIdentifier symmAlg, byte[] encSymmKey,
      AlgorithmIdentifier keyAlg, byte[] valueHint, byte[] encValue) {
    return BridgeAsn1Util.buildEncryptedValue(intendedAlg, symmAlg,
            encSymmKey, keyAlg, valueHint, encValue);
  }

}
