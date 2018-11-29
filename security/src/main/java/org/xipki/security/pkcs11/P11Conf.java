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

package org.xipki.security.pkcs11;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.password.PasswordResolver;
import org.xipki.security.pkcs11.conf.MechanismSetType;
import org.xipki.security.pkcs11.conf.ModuleType;
import org.xipki.security.pkcs11.conf.Pkcs11conf;
import org.xipki.util.Args;
import org.xipki.util.conf.InvalidConfException;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11Conf {

  private final Map<String, P11ModuleConf> moduleConfs;

  private final Set<String> moduleNames;

  public P11Conf(InputStream confStream, PasswordResolver passwordResolver)
      throws InvalidConfException, IOException {
    Args.notNull(confStream, "confStream");
    try {
      Pkcs11conf pkcs11Conf = JSON.parseObject(confStream, Pkcs11conf.class);
      pkcs11Conf.validate();

      List<ModuleType> moduleTypes = pkcs11Conf.getModules();
      List<MechanismSetType> mechanismSets = pkcs11Conf.getMechanismSets();

      Map<String, P11ModuleConf> confs = new HashMap<>();
      for (ModuleType moduleType : moduleTypes) {
        P11ModuleConf conf = new P11ModuleConf(moduleType, mechanismSets, passwordResolver);
        confs.put(conf.getName(), conf);
      }

      if (!confs.containsKey(P11CryptServiceFactory.DEFAULT_P11MODULE_NAME)) {
        throw new InvalidConfException("module '"
            + P11CryptServiceFactory.DEFAULT_P11MODULE_NAME + "' is not defined");
      }
      this.moduleConfs = Collections.unmodifiableMap(confs);
      this.moduleNames = Collections.unmodifiableSet(new HashSet<>(confs.keySet()));
    } catch (IOException | RuntimeException ex) {
      throw new InvalidConfException("invalid PKCS#11 configuration", ex);
    } finally {
      confStream.close();
    }
  }

  public Set<String> getModuleNames() {
    return moduleNames;
  }

  public P11ModuleConf getModuleConf(String moduleName) {
    return moduleConfs.get(moduleName);
  }

}
