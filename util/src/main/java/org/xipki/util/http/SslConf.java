/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.util.http;

import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Configuration of SSL.
 *
 * @author Lijun Liao
 */
public class SslConf extends ValidatableConf {

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
    notBlank(name, "name");
  }

} // class Ssl
