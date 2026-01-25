// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.security.util.EcCurveEnum;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * @author Lijun Liao (xipki)
 */
public enum KeySpec {
  // RSA
  RSA2048("RSA-2048", PKCS11KeyPairType.RSA_2048),
  RSA3072("RSA-3072", PKCS11KeyPairType.RSA_3072),
  RSA4096("RSA-4096", PKCS11KeyPairType.RSA_4096),
  // EC
  SECP256R1("SECP256R1", PKCS11KeyPairType.EC_P256),
  SECP384R1("SECP384R1", PKCS11KeyPairType.EC_P384),
  SECP521R1("SECP521R1", PKCS11KeyPairType.EC_P521),
  /** BrainPool P256R1 EC Key */
  BRAINPOOLP256R1("BRAINPOOLP256R1", PKCS11KeyPairType.EC_BrainpoolP256R1),
  /** BrainPool P384R1 EC Key */
  BRAINPOOLP384R1("BRAINPOOLP384R1", PKCS11KeyPairType.EC_BrainpoolP384R1),
  /** BrainPool P512R1 EC Key */
  BRAINPOOLP512R1("BRAINPOOLP512R1", PKCS11KeyPairType.EC_BrainpoolP512R1),
  SM2P256V1("SM2P256V1", PKCS11KeyPairType.SM2),
  FRP256V1 ("FRP256V1", PKCS11KeyPairType.EC_FRP256V1),
  // Edwards and Montgomery EC key
  X25519("X25519",   PKCS11KeyPairType.X25519),
  X448  (  "X448",   PKCS11KeyPairType.X448),
  ED25519("ED25519", PKCS11KeyPairType.ED25519),
  ED448  ("ED448",   PKCS11KeyPairType.ED448),
  // PQC MLDSA (Dilithium)
  MLDSA44("MLDSA44", PKCS11KeyPairType.MLDSA44),
  MLDSA65("MLDSA65", PKCS11KeyPairType.MLDSA65),
  MLDSA87("MLDSA87", PKCS11KeyPairType.MLDSA87),
  // PQC ML-KEM (Kyber)
  MLKEM512 ("MLKEM512",  PKCS11KeyPairType.MLKEM512),
  MLKEM768 ("MLKEM768",  PKCS11KeyPairType.MLKEM768),
  MLKEM1024("MLKEM1024", PKCS11KeyPairType.MLKEM1024),

  // Composite MLDSA + Trad key
  MLDSA44_RSA2048_PSS_SHA256(MLDSA44, RSA2048,
      OIDs.Composite.id_MLDSA44_RSA2048_PSS_SHA256),
  MLDSA44_RSA2048_PKCS15_SHA256(MLDSA44, RSA2048,
      OIDs.Composite.id_MLDSA44_RSA2048_PKCS15_SHA256),
  MLDSA44_ED25519_SHA512(MLDSA44, ED25519,
      OIDs.Composite.id_MLDSA44_Ed25519_SHA512),
  MLDSA44_ECDSA_P256_SHA256(MLDSA44, SECP256R1,
      OIDs.Composite.id_MLDSA44_ECDSA_P256_SHA256),
  MLDSA65_RSA3072_PSS_SHA512(MLDSA65, RSA3072,
      OIDs.Composite.id_MLDSA65_RSA3072_PSS_SHA512),
  MLDSA65_RSA3072_PKCS15_SHA512(MLDSA65, RSA3072,
      OIDs.Composite.id_MLDSA65_RSA3072_PKCS15_SHA512),
  MLDSA65_RSA4096_PSS_SHA512(MLDSA65, RSA4096,
      OIDs.Composite.id_MLDSA65_RSA4096_PSS_SHA512),
  MLDSA65_RSA4096_PKCS15_SHA512(MLDSA65, RSA4096,
      OIDs.Composite.id_MLDSA65_RSA4096_PKCS15_SHA512),
  MLDSA65_ECDSA_P256_SHA512(MLDSA65, SECP256R1,
      OIDs.Composite.id_MLDSA65_ECDSA_P256_SHA512),
  MLDSA65_ECDSA_P384_SHA512(MLDSA65, SECP384R1,
      OIDs.Composite.id_MLDSA65_ECDSA_P384_SHA512),
  MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512(MLDSA65, BRAINPOOLP256R1,
      OIDs.Composite.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512),
  MLDSA65_ED25519_SHA512(MLDSA65, ED25519,
      OIDs.Composite.id_MLDSA65_Ed25519_SHA512),
  MLDSA87_ECDSA_P384_SHA512(MLDSA87, SECP384R1,
      OIDs.Composite.id_MLDSA87_ECDSA_P384_SHA512),
  MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512(MLDSA87, BRAINPOOLP384R1,
      OIDs.Composite.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512),
  MLDSA87_ED448_SHAKE256(MLDSA87, ED448,
      OIDs.Composite.id_MLDSA87_Ed448_SHAKE256),
  MLDSA87_RSA3072_PSS_SHA512(MLDSA87, RSA3072,
      OIDs.Composite.id_MLDSA87_RSA3072_PSS_SHA512),
  MLDSA87_RSA4096_PSS_SHA512(MLDSA87, RSA4096,
      OIDs.Composite.id_MLDSA87_RSA4096_PSS_SHA512),
  MLDSA87_ECDSA_P521_SHA512(MLDSA87, SECP521R1,
      OIDs.Composite.id_MLDSA87_ECDSA_P521_SHA512),

  // Composite KEM + Trad key
  /*
  MLKEM768_RSA2048_SHA3_256(MLKEM768, RSA2048,
      OIDs.Composite.id_MLKEM768_RSA2048_SHA3_256),
  MLKEM768_RSA3072_SHA3_256(MLKEM768, RSA3072,
      OIDs.Composite.id_MLKEM768_RSA3072_SHA3_256),
  MLKEM768_RSA4096_SHA3_256(MLKEM768, RSA4096,
      OIDs.Composite.id_MLKEM768_RSA4096_SHA3_256),
  MLKEM768_X25519_SHA3_256(MLKEM768, X25519,
      OIDs.Composite.id_MLKEM768_X25519_SHA3_256),
  MLKEM768_ECDH_P256_SHA3_256(MLKEM768, SECP256R1,
      OIDs.Composite.id_MLKEM768_ECDH_P256_SHA3_256),
  MLKEM768_ECDH_P384_SHA3_256(MLKEM768, SECP384R1,
      OIDs.Composite.id_MLKEM768_ECDH_P384_SHA3_256),
  MLKEM768_ECDH_BP256_SHA3_256(MLKEM768, BRAINPOOLP256R1,
      OIDs.Composite.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256),
  MLKEM1024_RSA3072_SHA3_256(MLKEM1024, RSA3072,
      OIDs.Composite.id_MLKEM1024_RSA3072_SHA3_256),
  MLKEM1024_ECDH_P384_SHA3_256(MLKEM1024, SECP384R1,
      OIDs.Composite.id_MLKEM1024_ECDH_P384_SHA3_256),
  MLKEM1024_ECDH_BP384_SHA3_256(MLKEM1024, BRAINPOOLP384R1,
      OIDs.Composite.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256),
  MLKEM1024_X448_SHA3_256(MLKEM1024, X448,
      OIDs.Composite.id_MLKEM1024_X448_SHA3_256),
  MLKEM1024_ECDH_P521_SHA3_256(MLKEM1024, SECP521R1,
      OIDs.Composite.id_MLKEM1024_ECDH_P521_SHA3_256)
   */
  ;

  private final String text;

  private final AlgorithmIdentifier algId;

  private final PKCS11KeyPairType type;

  private final KeySpec compositePqcVariant;

  private final KeySpec compositeTradVariant;

  KeySpec(KeySpec compositePqcVariant,
          KeySpec compositeTradVariant, ASN1ObjectIdentifier oid) {
    this.text = name().replace('_', '-');
    this.compositePqcVariant  = compositePqcVariant;
    this.compositeTradVariant = compositeTradVariant;
    this.algId = new AlgorithmIdentifier(oid);
    this.type = null;
  }

  KeySpec(String text, PKCS11KeyPairType type) {
    this.compositePqcVariant  = null;
    this.compositeTradVariant = null;
    this.text = text;
    this.type = type;
    if (type instanceof PKCS11KeyPairType.RSA) {
      this.algId = new AlgorithmIdentifier(
          OIDs.Algo.id_rsaEncryption, DERNull.INSTANCE);
    } else if (type instanceof PKCS11KeyPairType.GenericEC){
      ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(
          ((PKCS11KeyPairType.GenericEC) type).getCurveOid());
      if (type instanceof PKCS11KeyPairType.EC
          || type instanceof PKCS11KeyPairType.SM2) {
        this.algId = new AlgorithmIdentifier(
            OIDs.Algo.id_ecPublicKey, curveOid);
      } else {
        this.algId = new AlgorithmIdentifier(curveOid);
      }
    } else if (type instanceof PKCS11KeyPairType.MLDSA) {
      long variant = ((PKCS11KeyPairType.MLDSA) type).getVariant();
      ASN1ObjectIdentifier oid =
            variant == PKCS11T.CKP_ML_DSA_44 ? OIDs.Algo.id_ml_dsa_44
          : variant == PKCS11T.CKP_ML_DSA_65 ? OIDs.Algo.id_ml_dsa_65
          : OIDs.Algo.id_ml_dsa_87;

      this.algId = new AlgorithmIdentifier(oid);
    } else if (type instanceof PKCS11KeyPairType.MLKEM) {
      long variant = ((PKCS11KeyPairType.MLKEM) type).getVariant();
      ASN1ObjectIdentifier oid =
            variant == PKCS11T.CKP_ML_KEM_512
                ? OIDs.Algo.id_ml_kem_512
          : variant == PKCS11T.CKP_ML_KEM_768
                ? OIDs.Algo.id_ml_kem_768
          : OIDs.Algo.id_ml_kem_1024;

      this.algId = new AlgorithmIdentifier(oid);
    } else {
      throw new IllegalArgumentException("invalid type " + type.getClass());
    }
  }

  public boolean isRSA() {
    return type instanceof PKCS11KeyPairType.RSA;
  }

  public Integer getRSAKeyBitSize() {
    if (type instanceof PKCS11KeyPairType.RSA) {
      return ((PKCS11KeyPairType.RSA) type).getModulusBits();
    } else {
      return null;
    }
  }

  public boolean isWeierstrassEC() {
    return type instanceof PKCS11KeyPairType.EC
        || type instanceof PKCS11KeyPairType.SM2;
  }

  public boolean isEdwardsEC() {
    return type instanceof PKCS11KeyPairType.ECEdwards;
  }

  public boolean isMontgomeryEC() {
    return type instanceof PKCS11KeyPairType.ECMontgomery;
  }

  public boolean isMldsa() {
    return type instanceof PKCS11KeyPairType.MLDSA;
  }

  public boolean isMlkem() {
    return type instanceof PKCS11KeyPairType.MLKEM;
  }

  public boolean isCompositeMLDSA() {
    String name = name();
    if (name.startsWith("MLDSA")) {
      return name.startsWith("MLDSA44_") ||
          name.startsWith("MLDSA65_") ||
          name.startsWith("MLDSA87_");
    }
    return false;
  }

  public boolean isCompositeMLKEM() {
    String name = name();
    if (name.startsWith("MLKEM")) {
      return name.startsWith("MLKEM512_") ||
          name.startsWith("MLKEM768_") ||
          name.startsWith("MLKEM1024_");
    }
    return false;
  }

  public boolean isComposite() {
    return isCompositeMLDSA() ||isCompositeMLKEM();
  }

  public EcCurveEnum getEcCurve() {
    switch (this) {
      case SECP256R1:
        return EcCurveEnum.SECP256R1;
      case SECP384R1:
        return EcCurveEnum.SECP384R1;
      case SECP521R1:
        return EcCurveEnum.SECP521R1;
      case BRAINPOOLP256R1:
        return EcCurveEnum.BRAINPOOLP256R1;
      case BRAINPOOLP384R1:
        return EcCurveEnum.BRAINPOOLP384R1;
      case BRAINPOOLP512R1:
        return EcCurveEnum.BRAINPOOLP512R1;
      case SM2P256V1:
        return EcCurveEnum.SM2P256V1;
      case FRP256V1:
        return EcCurveEnum.FRP256V1;
      case ED25519:
        return EcCurveEnum.ED25519;
      case ED448:
        return EcCurveEnum.ED448;
      case X25519:
        return EcCurveEnum.X25519;
      case X448:
        return EcCurveEnum.X448;
      default:
        return null;
    }
  }

  public Integer getEcCurveFieldByteSize() {
    EcCurveEnum curve = getEcCurve();
    return curve == null ? null : getEcCurveFieldByteSize();
  }

  public String getText() {
    return text;
  }

  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algId;
  }

  public PKCS11KeyPairType getType() {
    return type;
  }

  public KeySpec getCompositePqcVariant() {
    return compositePqcVariant;
  }

  public KeySpec getCompositeTradVariant() {
    return compositeTradVariant;
  }

  public static KeySpec ofPublicKey(SubjectPublicKeyInfo keyInfo) {
    AlgorithmIdentifier keyAlgId = keyInfo.getAlgorithm();

    if (keyAlgId.getAlgorithm().equals(OIDs.Algo.id_rsaEncryption)) {
      RSAPublicKey rsa = RSAPublicKey.getInstance(
          keyInfo.getPublicKeyData().getOctets());

      return ofRSA(rsa.getModulus().bitLength());
    } else {
      return ofAlgorithmIdentifier(keyInfo.getAlgorithm());
    }
  }

  public static KeySpec ofAlgorithmIdentifier(AlgorithmIdentifier keyAlgId) {
    ASN1ObjectIdentifier keyAlgOid = keyAlgId.getAlgorithm();

    if (keyAlgOid.equals(OIDs.Algo.id_ecPublicKey)) {
      ASN1ObjectIdentifier curveOid =
          ASN1ObjectIdentifier.getInstance(keyAlgId.getParameters());

      for (KeySpec spec : KeySpec.values()) {
        if (spec.isWeierstrassEC()) {
          if (curveOid.equals(spec.algId.getParameters())) {
            return spec;
          }
        }
      }
    } else {
      for (KeySpec spec : KeySpec.values()) {
        if (spec.isRSA() || spec.isWeierstrassEC()) {
          continue;
        }

        if (spec.algId.getAlgorithm().equals(keyAlgOid)) {
          return spec;
        }
      }
    }

    return null;
  }

  public static KeySpec ofRSA(int modulusBitLength) {
    switch (modulusBitLength) {
      case 2048: return KeySpec.RSA2048;
      case 3072: return KeySpec.RSA3072;
      case 4096: return KeySpec.RSA4096;
      default: return null;
    }
  }

  public static KeySpec ofEcCurve(EcCurveEnum curve) {
    switch (curve) {
      case SECP256R1: return KeySpec.SECP256R1;
      case SECP384R1: return KeySpec.SECP384R1;
      case SECP521R1: return KeySpec.SECP521R1;
      case BRAINPOOLP256R1: return KeySpec.BRAINPOOLP256R1;
      case BRAINPOOLP384R1: return KeySpec.BRAINPOOLP384R1;
      case BRAINPOOLP512R1: return KeySpec.BRAINPOOLP512R1;
      case SM2P256V1: return KeySpec.SM2P256V1;
      case FRP256V1:  return KeySpec.FRP256V1;
      case ED25519:   return KeySpec.ED25519;
      case ED448:     return KeySpec.ED448;
      case X25519:    return KeySpec.X25519;
      case X448:      return KeySpec.X448;
      default:        return null;
    }
  }

  public static List<KeySpec> ofKeySpecs(List<String> names)
      throws NoSuchAlgorithmException {
    List<KeySpec> list = new ArrayList<>(names.size());
    for (String name : names) {
      list.add(ofKeySpec(name));
    }
    return list;
  }

  public static KeySpec ofKeySpec(String name) throws NoSuchAlgorithmException {
    name = name.trim().toUpperCase(Locale.ROOT);
    String name2 = name.replace('_', '-');
    String name3 = name2.replaceAll("-", "").replace("/", "");

    for (KeySpec m : KeySpec.values()) {
      String n = m.name();
      if (     n.equals(name) || n.equals(name2) || n.equals(name3) ||
          m.text.equals(name) || m.text.equals(name2) || m.text.equals(name3)) {
        return m;
      }
    }

    throw new NoSuchAlgorithmException("unknown KeySpec " + name);
  }

}
