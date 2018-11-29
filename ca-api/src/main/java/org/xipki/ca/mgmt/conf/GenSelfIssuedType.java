/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.mgmt.conf;

import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class GenSelfIssuedType extends ValidatableConf {

  private FileOrBinary csr;

  private String profile;

  private String serialNumber;

  /**
   * Output format of the generated certificate
   */
  private String certOutform;

  public FileOrBinary getCsr() {
    return csr;
  }

  public void setCsr(FileOrBinary csr) {
    this.csr = csr;
  }

  public String getProfile() {
    return profile;
  }

  public void setProfile(String profile) {
    this.profile = profile;
  }

  public String getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(String serialNumber) {
    this.serialNumber = serialNumber;
  }

  public String getCertOutform() {
    return certOutform;
  }

  public void setCertOutform(String certOutform) {
    this.certOutform = certOutform;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(csr, "csr");
    validate(csr);
  }

}
