// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class KeyCertBytesPair {

  private final byte[] key;

  private final byte[] cert;

  public KeyCertBytesPair(byte[] key, byte[] cert) {
    this.key = key;
    this.cert = cert;
  }

  public byte[] key() {
    return key;
  }

  public byte[] cert() {
    return cert;
  }
}
