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

package org.xipki.ca.gateway.conf;

import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.List;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class SignerConf extends ValidatableConf {

  private List<FileOrBinary> certs;

  private String type;

  private String conf;

  public List<FileOrBinary> getCerts() {
    return certs;
  }

  public void setCerts(List<FileOrBinary> certs) {
    this.certs = certs;
  }

  public String getType() {
      return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getConf() {
    return conf;
  }

  public void setConf(String conf) {
    this.conf = conf;
  }

  @Override
  public void validate() throws InvalidConfException {
    notBlank(type, "type");
    notBlank(conf, "conf");
  }

}
