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

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Pkcs11conf extends ValidatableConf {

  /**
   * exactly one module must have the name 'default'.
   */
  private List<ModuleType> modules;

  private List<MechanismSetType> mechanismSets;

  public List<ModuleType> getModules() {
    return modules;
  }

  public void setModules(List<ModuleType> modules) {
    if (modules == null) {
      modules = new LinkedList<>();
    }
    this.modules = modules;
  }

  public List<MechanismSetType> getMechanismSets() {
    if (mechanismSets == null) {
      mechanismSets = new LinkedList<>();
    }
    return mechanismSets;
  }

  public void setMechanismSets(List<MechanismSetType> mechanismSets) {
    this.mechanismSets = mechanismSets;
  }

  public void addModule(ModuleType module) {
    getModules().add(module);
  }

  public void addMechanismSet(MechanismSetType mechanismSet) {
    getMechanismSets().add(mechanismSet);
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(modules, "modules");
    validate(modules);
    notEmpty(mechanismSets, "mechanismSets");
    validate(mechanismSets);
  }

}
