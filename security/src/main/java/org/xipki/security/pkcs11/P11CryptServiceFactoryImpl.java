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

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.PasswordResolver;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.emulator.EmulatorP11Module;
import org.xipki.security.pkcs11.iaik.IaikP11Module;
import org.xipki.security.pkcs11.proxy.ProxyP11Module;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11CryptServiceFactoryImpl implements P11CryptServiceFactory {

  private static final Logger LOG = LoggerFactory.getLogger(P11CryptServiceFactoryImpl.class);

  private static final Map<String, P11CryptService> services = new HashMap<>();

  private static final Map<String, P11Module> modules = new HashMap<>();

  private PasswordResolver passwordResolver;

  private P11Conf p11Conf;

  private String pkcs11ConfFile;

  public synchronized void init() throws InvalidConfException, IOException {
    if (p11Conf != null) {
      return;
    }
    if (StringUtil.isBlank(pkcs11ConfFile)) {
      LOG.error("no pkcs11ConfFile is configured, could not initialize");
      return;
    }

    this.p11Conf = new P11Conf(new FileInputStream(pkcs11ConfFile), passwordResolver);
  }

  public synchronized P11CryptService getP11CryptService(String moduleName)
      throws XiSecurityException, P11TokenException {
    if (p11Conf == null) {
      throw new IllegalStateException("please set pkcs11ConfFile and then call init() first");
    }

    final String name = getModuleName(moduleName);
    P11ModuleConf conf = p11Conf.moduleConf(name);
    if (conf == null) {
      throw new XiSecurityException("PKCS#11 module " + name + " is not defined");
    }

    P11CryptService instance = services.get(moduleName);
    if (instance != null) {
      return instance;
    }

    String nativeLib = conf.nativeLibrary();
    String type = conf.type().toLowerCase();

    P11Module p11Module = modules.get(nativeLib);
    if (p11Module == null) {
      if (type.equals(ProxyP11Module.TYPE)) {
        p11Module = ProxyP11Module.getInstance(conf);
      } else if (type.equals(EmulatorP11Module.TYPE)) {
        p11Module = EmulatorP11Module.getInstance(conf);
      } else if (type.equalsIgnoreCase(IaikP11Module.TYPE)) {
        p11Module = IaikP11Module.getInstance(conf);
      } else {
        throw new XiSecurityException("Unknown module type " + type + "'");
      }
    }

    modules.put(nativeLib, p11Module);
    instance = new P11CryptService(p11Module);
    services.put(moduleName, instance);

    return instance;
  }

  private String getModuleName(String moduleName) {
    return (moduleName == null) ? DEFAULT_P11MODULE_NAME : moduleName;
  }

  public void setPkcs11ConfFile(String confFile) {
    this.pkcs11ConfFile = StringUtil.isBlank(confFile) ? null : confFile;
  }

  public void setPasswordResolver(PasswordResolver passwordResolver) {
    this.passwordResolver = passwordResolver;
  }

  public void shutdown() {
    for (String pk11Lib : modules.keySet()) {
      try {
        modules.get(pk11Lib).close();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not close PKCS11 Module " + pk11Lib);
      }
    }
    modules.clear();
    services.clear();
  }

  @Override
  public Set<String> moduleNames() {
    if (p11Conf == null) {
      throw new IllegalStateException("pkcs11ConfFile is not set");
    }
    return p11Conf.moduleNames();
  }

}
