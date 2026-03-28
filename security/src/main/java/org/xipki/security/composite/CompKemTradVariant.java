// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.xipki.security.KeySpec;

/**
 * Comp Kem Trad Variant enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum CompKemTradVariant {

  X25519(KeySpec.X25519, 32),
  X448(KeySpec.X448, 56),
  ECDH_P256(KeySpec.P256, 32),
  ECDH_P384(KeySpec.P384, 48),
  ECDH_P521(KeySpec.P521, 66),
  ECDH_BP256(KeySpec.BRAINPOOLP256R1, 32),
  ECDH_BP384(KeySpec.BRAINPOOLP384R1, 48),
  RSA2048_OAEP(KeySpec.RSA2048, 0),
  RSA3072_OAEP(KeySpec.RSA3072, 0),
  RSA4096_OAEP(KeySpec.RSA4096, 0);

  private final KeySpec keySpec;

  private final int ecdhSize;

  CompKemTradVariant(KeySpec keySpec, int ecdhSize) {
    this.keySpec = keySpec;
    this.ecdhSize = ecdhSize;
  }

  public KeySpec keySpec() {
    return keySpec;
  }

  public int ecdhSize() {
    return ecdhSize;
  }

  public static CompKemTradVariant ofKeySpec(KeySpec keySpec) {
    for (CompKemTradVariant v : CompKemTradVariant.values()) {
      if (v.keySpec == keySpec) {
        return v;
      }
    }
    return null;
  }

}
