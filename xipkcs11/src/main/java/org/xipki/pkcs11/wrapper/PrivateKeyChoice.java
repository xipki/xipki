// Copyright (c) 2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper;

import org.xipki.util.codec.Args;

import java.security.PrivateKey;

/**
 * @author Lijun Liao (xipki)
 */
public class PrivateKeyChoice {

  private final PrivateKey keyObject;

  private final byte[] encodedKey;

  public PrivateKeyChoice(PrivateKey keyObject) {
    this.keyObject = Args.notNull(keyObject, "keyObject");
    this.encodedKey = null;
  }

  public PrivateKeyChoice(byte[] encodedKey) {
    this.keyObject = null;
    this.encodedKey = Args.notNull(encodedKey, "encodedKey");
  }

  public PrivateKey getKeyObject() {
    return keyObject;
  }

  public byte[] getEncoded() {
    return encodedKey != null ? encodedKey : keyObject.getEncoded();
  }

}
