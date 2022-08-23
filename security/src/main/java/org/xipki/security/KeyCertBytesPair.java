package org.xipki.security;

/**
 *
 * @author Lijun Liao
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
