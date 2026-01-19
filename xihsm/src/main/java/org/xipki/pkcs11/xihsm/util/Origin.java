// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.util;

/**
 * @author Lijun Liao (xipki)
 */
public enum Origin {

  // Via C_GenerateKey or C_GenerateKeyPair
  GENERATE(1),

  // Via C_CreateObject
  CREATE_OBJECT(2),

  // Via C_UnwrapKey
  UNWRAP_KEY(3),

  // Via C_DeriveKey
  DERIVE_KEY(4);

  private final long code;

  Origin(int code) {
    this.code = code;
  }

  public long getCode() {
    return code;
  }

  public static Origin ofCode(long code) {
    for (Origin m : Origin.values()) {
      if (m.code == code) {
        return m;
      }
    }
    throw new IllegalArgumentException("invalid code " + code);
  }

}
