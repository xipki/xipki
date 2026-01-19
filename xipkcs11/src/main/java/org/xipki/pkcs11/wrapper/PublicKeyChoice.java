// Copyright (c) 2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper;

import org.xipki.util.codec.Args;

import java.security.PublicKey;

/**
 * @author Lijun Liao (xipki)
 */
public class PublicKeyChoice {

  private final PublicKey keyObject;

  private final byte[] encodedKey;

  public PublicKeyChoice(PublicKey keyObject) {
    this.keyObject = Args.notNull(keyObject, "keyObject");
    this.encodedKey = null;
  }

  public PublicKeyChoice(byte[] encodedKey) {
    this.keyObject = null;
    this.encodedKey = Args.notNull(encodedKey, "encodedKey");
  }

  public PublicKey getKeyObject() {
    return keyObject;
  }

  public byte[] getEncoded() {
    return encodedKey != null ? encodedKey : keyObject.getEncoded();
  }

}
