// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

/**
 * Keystore configuration.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class KeystoreConf {

  private String type;

  private String password;

  private String keystore;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getKeystore() {
    return keystore;
  }

  public void setKeystore(String keystore) {
    this.keystore = keystore;
  }
}
