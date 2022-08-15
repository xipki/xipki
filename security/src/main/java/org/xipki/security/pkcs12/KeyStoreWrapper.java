/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs12;

import org.xipki.util.Args;

import java.security.KeyStore;

/**
 * Keystore wrapper (containing the keystore object and its encoded form).
 *
 * @author Lijun Liao
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
