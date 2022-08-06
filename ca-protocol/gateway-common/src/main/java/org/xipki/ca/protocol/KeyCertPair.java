package org.xipki.ca.protocol;

public class KeyCertPair {

  private final byte[] key;

  private final byte[] certificate;

  public KeyCertPair(byte[] key, byte[] certificate) {
    this.key = key;
    this.certificate = certificate;
  }

  public byte[] getKey() {
    return key;
  }

  public byte[] getCertificate() {
    return certificate;
  }
}
