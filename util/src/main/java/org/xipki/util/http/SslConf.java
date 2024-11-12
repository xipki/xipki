// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Configuration of SSL.
 *
 * @author Lijun Liao (xipki)
 */
public class SslConf extends ValidableConf {

  private String name;

  private String storeType;

  private FileOrBinary keystore;

  private String keystorePassword;

  private FileOrBinary[] trustanchors;

  /**
   * Valid values are {@code null}, no_op, default, or java:{qualified class name}
   * (without the brackets).
   */
  private String hostnameVerifier;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getStoreType() {
    return storeType;
  }

  public void setStoreType(String storeType) {
    this.storeType = storeType;
  }

  public FileOrBinary getKeystore() {
    return keystore;
  }

  public void setKeystore(FileOrBinary keystore) {
    this.keystore = keystore;
  }

  public String getKeystorePassword() {
    return keystorePassword;
  }

  public void setKeystorePassword(String keystorePassword) {
    this.keystorePassword = keystorePassword;
  }

  public FileOrBinary[] getTrustanchors() {
    return trustanchors;
  }

  public void setTrustanchors(FileOrBinary[] trustanchors) {
    this.trustanchors = trustanchors;
  }

  public String getHostnameVerifier() {
    return hostnameVerifier;
  }

  public void setHostnameVerifier(String hostnameVerifier) {
    this.hostnameVerifier = hostnameVerifier;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

}
