// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.security.SecureRandom;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class BridgeKEMUtil {

  private static final String id_ml_kem_512 = "2.16.840.1.101.3.4.4.1";
  private static final String id_ml_kem_768 = "2.16.840.1.101.3.4.4.2";
  private static final String id_ml_kem_1024 = "2.16.840.1.101.3.4.4.3";

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

  private static MLKEMParameters getMLKEMVariant(BridgeMlkemVariant variant) {
    return variant == BridgeMlkemVariant.mlkem512 ? MLKEMParameters.ml_kem_512
        : variant == BridgeMlkemVariant.mlkem768 ? MLKEMParameters.ml_kem_768
        : MLKEMParameters.ml_kem_1024;
  }

  private static MLKEMPublicKeyParameters toPublicParameters(SubjectPublicKeyInfo pkInfo) {
    MLKEMParameters variant = getMLKEMVariant(pkInfo.getAlgorithm());
    return new MLKEMPublicKeyParameters(variant,
        BridgeAsn1Util.getPublicKeyData(pkInfo));
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
    } else if (tag == 0x0) {
      ASN1Primitive asn1Obj = BridgeAsn1Util.getImplicitBaseObject(
                  ASN1TaggedObject.getInstance(skData), BERTags.OCTET_STRING)
                  .toASN1Primitive();
      byte[] seed = ((ASN1OctetString) asn1Obj).getOctets();
      return new MLKEMPrivateKeyParameters(variant, seed);
    } else {
      throw new IllegalArgumentException("invalid tag " + (0xFF & tag));
    }
  }

  public static SecretWithEncapsulation encapsulateKey(
      SubjectPublicKeyInfo publicKeyInfo, SecureRandom rnd) {
    MLKEMGenerator gen = new MLKEMGenerator(rnd);
    MLKEMPublicKeyParameters pkParams = toPublicParameters(publicKeyInfo);
    return gen.generateEncapsulated(pkParams);
  }

  public static SecretWithEncapsulation encapsulateKey(
      BridgeMlkemVariant variant, byte[] publicKeyData, SecureRandom rnd) {
    MLKEMPublicKeyParameters pkParams = new MLKEMPublicKeyParameters(
        getMLKEMVariant(variant), publicKeyData);
    MLKEMGenerator gen = new MLKEMGenerator(rnd);
    return gen.generateEncapsulated(pkParams);
  }

  public static byte[] decapsulateKey(PrivateKeyInfo skInfo, byte[] encapKey) {
    MLKEMPrivateKeyParameters params = toPrivateParameters(skInfo);
    return new MLKEMExtractor(params).extractSecret(encapKey);
  }

  public static byte[] decapsulateKey(BridgeMlkemVariant variant, byte[] skValue, byte[] encapKey) {
    MLKEMPrivateKeyParameters dkObj =
        new MLKEMPrivateKeyParameters(getMLKEMVariant(variant), skValue);
    return new MLKEMExtractor(dkObj).extractSecret(encapKey);
  }

}
