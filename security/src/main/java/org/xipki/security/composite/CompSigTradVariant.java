// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.composite;

import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;

/**
 * Comp Sig Trad Variant enumeration.
 * {@link CompositeSigSuite}.
 * @author Lijun Liao (xipki)
 */
public enum CompSigTradVariant {

  Ed25519    (KeySpec.ED25519),
  Ed448      (KeySpec.ED448),
  ECDSA_P256 (KeySpec.P256),
  ECDSA_P384 (KeySpec.P384),
  ECDSA_P521 (KeySpec.P521),
  ECDSA_BP256(KeySpec.BRAINPOOLP256R1),
  ECDSA_BP384(KeySpec.BRAINPOOLP384R1),
  RSA2048_PSS(KeySpec.RSA2048),
  RSA3072_PSS(KeySpec.RSA3072),
  RSA4096_PSS(KeySpec.RSA4096);

  private final KeySpec keySpec;

  CompSigTradVariant(KeySpec keySpec) {
    this.keySpec = keySpec;
  }

  public SignAlgo signAlgo() {
    switch (this) {
      case Ed25519:
        return SignAlgo.ED25519;
      case Ed448:
        return SignAlgo.ED448;
      case ECDSA_P256:
      case ECDSA_BP256:
        return SignAlgo.ECDSA_SHA256;
      case ECDSA_P384:
      case ECDSA_BP384:
        return SignAlgo.ECDSA_SHA384;
      case ECDSA_P521:
        return SignAlgo.ECDSA_SHA512;
      case RSA2048_PSS:
      case RSA3072_PSS:
        return SignAlgo.RSAPSS_SHA256;
      case RSA4096_PSS:
        return SignAlgo.RSAPSS_SHA384;
      default:
        throw new IllegalStateException("shall not reach here");
    }
  }

  public KeySpec keySpec() {
    return keySpec;
  }

  public static CompSigTradVariant ofKeySpec(KeySpec keySpec) {
    for (CompSigTradVariant v : CompSigTradVariant.values()) {
      if (v.keySpec == keySpec) {
        return v;
      }
    }
    return null;
  }

}
