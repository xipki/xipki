// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.misc;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.io.FileOrBinary;

/**
 * Keystore configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class KeystoreConf {

  private final String type;

  private final String password;

  private final FileOrBinary keystore;

  public KeystoreConf(String type, String password, FileOrBinary keystore) {
    this.type = type;
    this.password = password;
    this.keystore = keystore;
  }

  public String type() {
    return type;
  }

  public String password() {
    return password;
  }

  public FileOrBinary keystore() {
    return keystore;
  }

  public static KeystoreConf parse(JsonMap json) throws CodecException {
    return new KeystoreConf(json.getString("type"),
        json.getString("password"),
        FileOrBinary.parse(json.getMap("keystore")));
  }

}
