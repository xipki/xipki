// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

/**
<<<<<<< ours
 * XiPKI component.
=======
 * Bridge Key Pair Bytes.
>>>>>>> theirs
 *
 * @author Lijun Liao (xipki)
 */
public class BridgeKeyPairBytes {

  private final byte[] privateKey;

  private final byte[] publicKey;

  public BridgeKeyPairBytes(byte[] privateKey, byte[] publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public byte[] privateKey() {
    return privateKey;
  }

  public byte[] publicKey() {
    return publicKey;
  }

}
