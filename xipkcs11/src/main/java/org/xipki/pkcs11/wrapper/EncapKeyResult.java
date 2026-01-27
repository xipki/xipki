// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * This class specifies the result of the C_EncapsulateKey.
 *
 * @author Lijun Liao (xipki)
 */
public class EncapKeyResult {

  private final long hKey;

  private final byte[] cipherText;

  public EncapKeyResult(long hKey, byte[] cipherText) {
    this.hKey = hKey;
    this.cipherText = cipherText;
  }

  public long hKey() {
    return hKey;
  }

  public byte[] cipherText() {
    return cipherText;
  }
}
