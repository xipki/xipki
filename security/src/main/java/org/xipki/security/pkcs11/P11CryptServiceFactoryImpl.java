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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.security.XiSecurityException;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11CryptServiceFactoryImpl implements P11CryptServiceFactory {

  private static final Logger LOG = LoggerFactory.getLogger(P11CryptServiceFactoryImpl.class);

  private static final Map<String, P11CryptService> services = new HashMap<>();

  private PasswordResolver passwordResolver;

  private Map<String, P11ModuleConf> moduleConfs;

  private Set<String> moduleNames;

  private String pkcs11ConfFile;

  private P11ModuleFactoryRegister p11ModuleFactoryRegister;

  public synchronized void init() throws InvalidConfException {
    if (moduleConfs != null) {
      return;
    }
    if (StringUtil.isBlank(pkcs11ConfFile)) {
      LOG.error("no pkcs11ConfFile is configured, could not initialize");
      return;
    }

    try (InputStream confStream = Files.newInputStream(Paths.get(pkcs11ConfFile))) {
      Pkcs11conf pkcs11Conf = JSON.parseObject(confStream, Pkcs11conf.class);
      pkcs11Conf.validate();

      List<Pkcs11conf.Module> moduleTypes = pkcs11Conf.getModules();
      List<Pkcs11conf.MechanismSet> mechanismSets = pkcs11Conf.getMechanismSets();

      Map<String, P11ModuleConf> confs = new HashMap<>();
      for (Pkcs11conf.Module moduleType : moduleTypes) {
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
      throw new InvalidConfException("could not create P11Conf: " + ex.getMessage(), ex);
    }
  }

  public void setP11ModuleFactoryRegister(P11ModuleFactoryRegister p11ModuleFactoryRegister) {
    this.p11ModuleFactoryRegister = p11ModuleFactoryRegister;
  }

  public synchronized P11CryptService getP11CryptService(String moduleName)
      throws XiSecurityException, P11TokenException {
    try {
      init();
    } catch (InvalidConfException ex) {
      throw new IllegalStateException(
          "could not initialize P11CryptServiceFactory: " + ex.getMessage(), ex);
    }

    if (moduleConfs == null) {
      throw new IllegalStateException("please set pkcs11ConfFile and then call init() first");
    }

    final String name = getModuleName(moduleName);
    P11ModuleConf conf = moduleConfs.get(name);
    if (conf == null) {
      throw new XiSecurityException("PKCS#11 module " + name + " is not defined");
    }

    P11CryptService instance = services.get(name);
    if (instance == null) {
      P11Module p11Module = p11ModuleFactoryRegister.getP11Module(conf);
      instance = new P11CryptService(p11Module);
      LOG.info("added PKCS#11 module {}\n{}", name, instance.getModule().getDescription());
      services.put(name, instance);
    }

    return instance;
  }

  private String getModuleName(String moduleName) {
    return (moduleName == null) ? DEFAULT_P11MODULE_NAME : moduleName;
  }

  public void setPkcs11ConfFile(String confFile) {
    if (StringUtil.isBlank(confFile)) {
      this.pkcs11ConfFile = null;
    } else {
      this.pkcs11ConfFile = IoUtil.expandFilepath(confFile);
    }
  }

  public void setPasswordResolver(PasswordResolver passwordResolver) {
    this.passwordResolver = passwordResolver;
  }

  @Override
  public void close() {
    services.clear();
  }

  @Override
  public Set<String> getModuleNames() {
    try {
      init();
    } catch (InvalidConfException ex) {
      throw new IllegalStateException(
          "could not initialize P11CryptServiceFactory: " + ex.getMessage(), ex);
    }
    return moduleNames;
  }

}
