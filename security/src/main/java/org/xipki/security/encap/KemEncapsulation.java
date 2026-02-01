// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.encap;

import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public class KemEncapsulation {

  // KMAC: derive mac key, MLKEM: encap, HMAC: mac computation
  public static final byte ALG_KMAC_MLKEM_HMAC = 1;
  public static final byte ALG_KMAC_COMPOSITE_MLKEM_HMAC = 2;

  private final byte alg;

  private final byte[] encapKey;

  private final byte[] encryptedSecret;

  public KemEncapsulation(byte alg, byte[] encapKey, byte[] encryptedSecret) {
    this.alg = alg;
    this.encapKey = Args.notNull(encapKey, "encapKey");
    Args.max(encapKey.length, "encapKey.length", 0xFFFF);

    this.encryptedSecret = Args.notNull(encryptedSecret, "encryptedSecret");
    Args.max(encryptedSecret.length, "encryptedSecret.length", 0xFFFF);
  }

  public byte alg() {
    return alg;
  }

  public byte[] encapKey() {
    return encapKey;
  }

  public byte[] encryptedSecret() {
    return encryptedSecret;
  }

}
