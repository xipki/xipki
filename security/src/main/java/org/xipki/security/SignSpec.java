// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public enum SignSpec {

  // RSA PKCS#1v1.5
  RSA_SHA256(SignAlgo.RSA_SHA256),
  RSA_SHA384(SignAlgo.RSA_SHA384),
  RSA_SHA512(SignAlgo.RSA_SHA512),

  RSA_SHA3_256(SignAlgo.RSA_SHA3_256),
  RSA_SHA3_384(SignAlgo.RSA_SHA3_384),
  RSA_SHA3_512(SignAlgo.RSA_SHA3_512),

  // RSA PSS with MGF1
  RSAPSS_SHA256(SignAlgo.RSAPSS_SHA256),
  RSAPSS_SHA384(SignAlgo.RSAPSS_SHA384),
  RSAPSS_SHA512(SignAlgo.RSAPSS_SHA512),

  RSAPSS_SHA3_256(SignAlgo.RSAPSS_SHA3_256),
  RSAPSS_SHA3_384(SignAlgo.RSAPSS_SHA3_384),
  RSAPSS_SHA3_512(SignAlgo.RSAPSS_SHA3_512),

  // RSA PSS with SHAKE

  RSAPSS_SHAKE128(SignAlgo.RSAPSS_SHAKE128),
  RSAPSS_SHAKE256(SignAlgo.RSAPSS_SHAKE256),

  ECDSA_SHA256(SignAlgo.ECDSA_SHA256),
  ECDSA_SHA384(SignAlgo.ECDSA_SHA384),
  ECDSA_SHA512(SignAlgo.ECDSA_SHA512),

  ECDSA_SHA3_256(SignAlgo.ECDSA_SHA3_256),
  ECDSA_SHA3_384(SignAlgo.ECDSA_SHA3_384),
  ECDSA_SHA3_512(SignAlgo.ECDSA_SHA3_512),

  // SM2
  SM2_SM3(SignAlgo.SM2_SM3),

  // ECDSA with SHAKE
  ECDSA_SHAKE128(SignAlgo.ECDSA_SHAKE128),
  ECDSA_SHAKE256(SignAlgo.ECDSA_SHAKE256),

  // EdDSA
  ED25519(SignAlgo.ED25519),

  ED448(SignAlgo.ED448),

  ML_DSA_44(SignAlgo.MLDSA44),
  ML_DSA_65(SignAlgo.MLDSA65),
  ML_DSA_87(SignAlgo.MLDSA87);

  private final SignAlgo algo;

  SignSpec(SignAlgo algo) {
    this.algo = algo;
  }

  public SignAlgo getAlgo() {
    return algo;
  }

  public static SignSpec ofSignSpec(SignAlgo signAlgo) {
    switch (signAlgo) {
      // ECDSA
      case ECDSA_SHA256:    return SignSpec.ECDSA_SHA256;
      case ECDSA_SHA384:    return SignSpec.ECDSA_SHA384;
      case ECDSA_SHA512:    return SignSpec.ECDSA_SHA512;
      case ECDSA_SHA3_256:  return SignSpec.ECDSA_SHA3_256;
      case ECDSA_SHA3_384:  return SignSpec.ECDSA_SHA3_384;
      case ECDSA_SHA3_512:  return SignSpec.ECDSA_SHA3_512;
      case ECDSA_SHAKE128:  return SignSpec.ECDSA_SHAKE128;
      case ECDSA_SHAKE256:  return SignSpec.ECDSA_SHAKE256;

      // RSA
      case RSA_SHA256:      return SignSpec.RSA_SHA256;
      case RSA_SHA384:      return SignSpec.RSA_SHA384;
      case RSA_SHA512:      return SignSpec.RSA_SHA512;
      case RSA_SHA3_256:    return SignSpec.RSA_SHA3_256;
      case RSA_SHA3_384:    return SignSpec.RSA_SHA3_384;
      case RSA_SHA3_512:    return SignSpec.RSA_SHA3_512;

      // RSA-PSS
      case RSAPSS_SHAKE128: return SignSpec.RSAPSS_SHAKE128;
      case RSAPSS_SHAKE256: return SignSpec.RSAPSS_SHAKE256;
      case RSAPSS_SHA256:   return SignSpec.RSAPSS_SHA256;
      case RSAPSS_SHA384:   return SignSpec.RSAPSS_SHA384;
      case RSAPSS_SHA512:   return SignSpec.RSAPSS_SHA512;
      case RSAPSS_SHA3_256: return SignSpec.RSAPSS_SHA3_256;
      case RSAPSS_SHA3_384: return SignSpec.RSAPSS_SHA3_384;
      case RSAPSS_SHA3_512: return SignSpec.RSAPSS_SHA3_512;
      // EDDSA
      case ED25519:         return SignSpec.ED25519;
      case ED448:           return SignSpec.ED448;
      // SM2
      case SM2_SM3:         return SignSpec.SM2_SM3;
      // ML-DSA
      case MLDSA44:       return SignSpec.ML_DSA_44;
      case MLDSA65:       return SignSpec.ML_DSA_65;
      case MLDSA87:       return SignSpec.ML_DSA_87;
      default: return null;
    }
  }

  public static List<SignSpec> ofSignSpecs(List<String> names)
      throws NoSuchAlgorithmException {
    List<SignSpec> list = new ArrayList<>(names.size());
    for (String name : names) {
      list.add(ofSignSpec(name));
    }
    return list;
  }

  public static SignSpec ofSignSpec(String name)
      throws NoSuchAlgorithmException {
    name = name.trim();
    String name2 = name.replace('-', '_');

    for (SignSpec m : SignSpec.values()) {
      String tname = m.name();
      if (tname.equalsIgnoreCase(name) || tname.equalsIgnoreCase(name2)) {
        return m;
      }
    }

    throw new NoSuchAlgorithmException("unknown SignSpec " + name);
  }
}
