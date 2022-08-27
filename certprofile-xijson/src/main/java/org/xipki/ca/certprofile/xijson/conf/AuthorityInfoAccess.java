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

package org.xipki.ca.certprofile.xijson.conf;

import com.alibaba.fastjson.annotation.JSONField;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Set;

/**
 * Extension AuthorityInfoAccess.
 *
 * @author Lijun Liao
 */

public class AuthorityInfoAccess extends ValidatableConf {

  @JSONField(ordinal = 1)
  private boolean includeCaIssuers;

  @JSONField(ordinal = 2)
  private boolean includeOcsp;

  @JSONField(ordinal = 3)
  private Set<String> ocspProtocols;

  @JSONField(ordinal = 3)
  private Set<String> caIssuersProtocols;

  public boolean isIncludeCaIssuers() {
    return includeCaIssuers;
  }

  public void setIncludeCaIssuers(boolean includeCaIssuers) {
    this.includeCaIssuers = includeCaIssuers;
  }

  public boolean isIncludeOcsp() {
    return includeOcsp;
  }

  public void setIncludeOcsp(boolean includeOcsp) {
    this.includeOcsp = includeOcsp;
  }

  public Set<String> getOcspProtocols() {
    return ocspProtocols;
  }

  public void setOcspProtocols(Set<String> ocspProtocols) {
    this.ocspProtocols = ocspProtocols;
  }

  public Set<String> getCaIssuersProtocols() {
    return caIssuersProtocols;
  }

  public void setCaIssuersProtocols(Set<String> caIssuersProtocols) {
    this.caIssuersProtocols = caIssuersProtocols;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

} // class AuthorityInfoAccess
