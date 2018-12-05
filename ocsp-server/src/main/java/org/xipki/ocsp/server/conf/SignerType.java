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

package org.xipki.ocsp.server.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.FileOrBinary;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class SignerType extends ValidatableConf {

  private String name;

  private String type;

  private String key;

  private List<String> algorithms;

  private FileOrBinary cert;

  private List<FileOrBinary> caCerts;

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

  public String getKey() {
    return key;
  }

  public void setKey(String key) {
    this.key = key;
  }

  public List<String> getAlgorithms() {
    if (algorithms == null) {
      algorithms = new LinkedList<>();
    }
    return algorithms;
  }

  public void setAlgorithms(List<String> algorithms) {
    this.algorithms = algorithms;
  }

  public FileOrBinary getCert() {
    return cert;
  }

  public void setCert(FileOrBinary cert) {
    this.cert = cert;
  }

  public List<FileOrBinary> getCaCerts() {
    if (caCerts == null) {
      caCerts = new LinkedList<>();
    }
    return caCerts;
  }

  public void setCaCerts(List<FileOrBinary> caCerts) {
    this.caCerts = caCerts;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    notEmpty(type, "type");
    notEmpty(key, "key");
    notEmpty(algorithms, "algorithms");
  }

}
