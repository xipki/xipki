/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.LogUtil;

/**
 * An implementation of {@link P11ModuleFactoryRegister}s.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class P11ModuleFactoryRegisterImpl implements P11ModuleFactoryRegister {

  private static final Logger LOG = LoggerFactory.getLogger(P11ModuleFactoryRegisterImpl.class);

  private static final Map<String, P11Module> modules = new HashMap<>();

  private ConcurrentLinkedDeque<P11ModuleFactory> factories =
      new ConcurrentLinkedDeque<P11ModuleFactory>();

  public void registFactory(P11ModuleFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("registFactory invoked with null.");
      return;
    }

    boolean replaced = factories.remove(factory);
    factories.add(factory);

    String action = replaced ? "replaced" : "added";
    LOG.info("{} P11ModuleFactory binding for {}", action, factory);
  }

  public void unregistFactory(P11ModuleFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("unregistFactory invoked with null.");
      return;
    }

    if (factories.remove(factory)) {
      LOG.info("removed P11ModuleFactory binding for {}", factory);
    } else {
      LOG.info("no P11ModuleFactory binding found to remove for '{}'", factory);
    }
  }

  @Override
  public P11Module getP11Module(P11ModuleConf conf) throws P11TokenException {
    String type = conf.getType().toLowerCase();

    String nativeLib = conf.getNativeLibrary();
    String key = type + ":" + nativeLib;

    P11Module p11Module = modules.get(key);

    if (p11Module == null) {
      for (P11ModuleFactory service : factories) {
        if (service.canCreateModule(type)) {
          p11Module = service.newModule(conf);
          break;
        }
      }

      if (p11Module == null) {
        throw new P11TokenException(
            "could not find Factory to create PKCS#11 module of type '" + type + "'");
      }
      modules.put(key, p11Module);
    }

    return p11Module;
  } // method getP11Module

  @Override
  public void close() {
    for (String pk11Lib : modules.keySet()) {
      try {
        modules.get(pk11Lib).close();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not close PKCS11 Module " + pk11Lib);
      }
    }
    modules.clear();

    factories.clear();
  } // method close

}
