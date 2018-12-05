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

package org.xipki.security.pkcs11.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class MechanismSetType extends ValidatableConf {

  private String name;

  /**
   * The mechanism. Set mechanism to ALL to accept all available mechanisms.
   */
  private List<String> mechanisms;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public List<String> getMechanisms() {
    if (mechanisms == null) {
      mechanisms = new LinkedList<>();
    }
    return mechanisms;
  }

  public void setMechanisms(List<String> mechanisms) {
    this.mechanisms = mechanisms;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    notEmpty(mechanisms, "mechanisms");
  }

}
