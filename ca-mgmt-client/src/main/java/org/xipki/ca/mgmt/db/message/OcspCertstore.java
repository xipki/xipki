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

package org.xipki.ca.mgmt.db.message;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class OcspCertstore extends ValidatableConf {

  private int version;

  private int countCerts;

  private String certhashAlgo;

  private List<OcspIssuer> issuers;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int getCountCerts() {
    return countCerts;
  }

  public void setCountCerts(int countCerts) {
    this.countCerts = countCerts;
  }

  public String getCerthashAlgo() {
    return certhashAlgo;
  }

  public void setCerthashAlgo(String certhashAlgo) {
    this.certhashAlgo = certhashAlgo;
  }

  public List<OcspIssuer> getIssuers() {
    if (issuers == null) {
      issuers = new LinkedList<>();
    }
    return issuers;
  }

  public void setIssuers(List<OcspIssuer> issuers) {
    this.issuers = issuers;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(certhashAlgo, "certhashAlgo");
    validate(issuers);
  }

}
