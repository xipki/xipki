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

package org.xipki.ca.server.mgmt.msg;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ChangeSignerRequest extends CommRequest {

  private String name;

  private String type;

  private String conf;

  private String base64Cert;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
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

  public String getBase64Cert() {
    return base64Cert;
  }

  public void setBase64Cert(String base64Cert) {
    this.base64Cert = base64Cert;
  }

}
