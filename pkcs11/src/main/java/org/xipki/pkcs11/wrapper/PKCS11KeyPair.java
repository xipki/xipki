// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * This class does not correspond to any PKCS#11 object. It is only a pair of
 * a private key and a public key.
 *
 * @author Lijun Liao (xipki)
 */
public class PKCS11KeyPair {

  /**
   * The public key of this key-pair.
   */
  private final long publicKey;

  /**
   * The private key of this key-pair.
   */
  private final long privateKey;

  /**
   * Constructor that takes a public and a private key. None can be null.
   *
   * @param publicKey
   *          The public key of the key-pair.
   * @param privateKey
   *          The private key of the key-pair.
   */
  public PKCS11KeyPair(long publicKey, long privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Get the public key part of this key-pair.
   *
   * @return The public key part of this key-pair.
   */
  public long getPublicKey() {
    return publicKey;
  }

  /**
   * Get the private key part of this key-pair.
   *
   * @return The private key part of this key-pair.
   */
  public long getPrivateKey() {
    return privateKey;
  }

  /**
   * Returns a string representation of the current object. The
   * output is only for debugging purposes and should not be used for other
   * purposes.
   *
   * @return A string presentation of this object for debugging output.
   */
  @Override
  public String toString() {
    return "  public key: " + publicKey + "\n  private key: " + privateKey;
  }

}
