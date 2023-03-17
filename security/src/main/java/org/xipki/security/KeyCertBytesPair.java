// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class KeyCertBytesPair {

  private final byte[] key;

  private final byte[] cert;

  public KeyCertBytesPair(byte[] key, byte[] cert) {
    this.key = key;
    this.cert = cert;
  }

  public byte[] getKey() {
    return key;
  }

  public byte[] getCert() {
    return cert;
  }
}
