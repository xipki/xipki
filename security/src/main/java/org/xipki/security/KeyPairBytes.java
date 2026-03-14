// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class KeyPairBytes {

  private final byte[] privateKey;

  private final byte[] publicKey;

  public KeyPairBytes(byte[] privateKey, byte[] publicKey) {
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
