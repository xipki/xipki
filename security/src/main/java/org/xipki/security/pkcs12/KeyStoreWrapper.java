// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.xipki.util.Args;

import java.security.KeyStore;

/**
 * Keystore wrapper (containing the keystore object and its encoded form).
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class KeyStoreWrapper {

  private final byte[] keystore;

  private KeyStore keystoreObject;

  public KeyStoreWrapper(byte[] keystore) {
    this.keystore = Args.notNull(keystore, "keystore");
  }

  public byte[] keystore() {
    return keystore;
  }

  public KeyStore keystoreObject() {
    return keystoreObject;
  }

  public void setKeystoreObject(KeyStore keystoreObject) {
    this.keystoreObject = keystoreObject;
  }

}
