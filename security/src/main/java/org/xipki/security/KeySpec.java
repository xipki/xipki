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
  // PQC ML-DSA (Dilithium)
  MLDSA44("ML-DSA-44", PKCS11KeyPairType.MLDSA44),
  MLDSA65("ML-DSA-65", PKCS11KeyPairType.MLDSA65),
  MLDSA87("ML-DSA-87", PKCS11KeyPairType.MLDSA87),
  // PQC ML-KEM (Kyber)
  MLKEM512 ("ML-KEM-512",  PKCS11KeyPairType.MLKEM512),
  MLKEM768 ("ML-KEM-768",  PKCS11KeyPairType.MLKEM768),
  MLKEM1024("ML-KEM-1024", PKCS11KeyPairType.MLKEM1024);

  private final String text;

  private final AlgorithmIdentifier algId;

  private final PKCS11KeyPairType type;

  KeySpec(String text, PKCS11KeyPairType type) {
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
    return type.getKeyType() == PKCS11T.CKK_RSA;
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
    String name3 = name2.replaceAll("-", "")
        .replace("/", "");

    for (KeySpec m : KeySpec.values()) {
      if (m.name().equals(name3) || m.text.equals(name)
          || m.text.equals(name2) || m.text.equals(name3)) {
        return m;
      }
    }

    throw new NoSuchAlgorithmException("unknown KeySpec " + name);
  }

}
