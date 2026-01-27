// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.xipki.security.KeySpec;

/**
 * @author Lijun Liao (xipki)
 */
public enum KemTradVariant {

  X25519(KeySpec.X25519),
  X448(KeySpec.X448),
  ECDH_P256(KeySpec.SECP256R1),
  ECDH_P384(KeySpec.SECP384R1),
  ECDH_P521(KeySpec.SECP521R1),
  ECDH_BP256(KeySpec.BRAINPOOLP256R1),
  ECDH_BP384(KeySpec.BRAINPOOLP384R1),
  RSA2048_OAEP(KeySpec.RSA2048),
  RSA3072_OAEP(KeySpec.RSA3072),
  RSA4096_OAEP(KeySpec.RSA4096);

  private final KeySpec keySpec;

  KemTradVariant(KeySpec keySpec) {
    this.keySpec = keySpec;
  }

  public KeySpec keySpec() {
    return keySpec;
  }

  public static KemTradVariant ofKeySpec(KeySpec keySpec) {
    for (KemTradVariant v : KemTradVariant.values()) {
      if (v.keySpec == keySpec) {
        return v;
      }
    }
    return null;
  }

}
