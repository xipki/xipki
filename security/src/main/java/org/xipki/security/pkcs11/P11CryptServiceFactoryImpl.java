// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.JSON;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * An implementation of {@link P11CryptServiceFactory}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11CryptServiceFactoryImpl implements P11CryptServiceFactory {

  private static final Logger LOG = LoggerFactory.getLogger(P11CryptServiceFactoryImpl.class);

  private static final Map<String, P11CryptService> services = new HashMap<>();

  private PasswordResolver passwordResolver;

  private Map<String, P11ModuleConf> moduleConfs;

  private Set<String> moduleNames;

  private String pkcs11ConfFile;

  private Pkcs11conf pkcs11Conf;

  private final P11ModuleFactoryRegister p11ModuleFactoryRegister;

  public P11CryptServiceFactoryImpl(P11ModuleFactoryRegister p11ModuleFactoryRegister) {
    this.p11ModuleFactoryRegister = p11ModuleFactoryRegister;
  }

  public synchronized void init() throws InvalidConfException {
    if (moduleConfs != null) {
      return;
    }

    if (pkcs11Conf == null && StringUtil.isBlank(pkcs11ConfFile)) {
      LOG.error("neither pkcs11Conf nor pkcs11ConfFile is configured, could not initialize");
      return;
    }

    if (pkcs11Conf == null) {
      try (InputStream confStream = Files.newInputStream(Paths.get(pkcs11ConfFile))) {
        pkcs11Conf = JSON.parseObject(confStream, Pkcs11conf.class);
        pkcs11Conf.validate();
      } catch (IOException ex) {
        throw new InvalidConfException("could not create P11Conf: " + ex.getMessage(), ex);
      }
    }

    try {
      List<Pkcs11conf.Module> moduleTypes = pkcs11Conf.getModules();
      List<Pkcs11conf.MechanismSet> mechanismSets = pkcs11Conf.getMechanismSets();

      Map<String, P11ModuleConf> confs = new HashMap<>();
      for (Pkcs11conf.Module moduleType : moduleTypes) {
        P11ModuleConf conf = new P11ModuleConf(moduleType, mechanismSets, passwordResolver);
        confs.put(conf.getName(), conf);
      }

      if (!confs.containsKey(P11CryptServiceFactory.DEFAULT_P11MODULE_NAME)) {
        throw new InvalidConfException("module '" + P11CryptServiceFactory.DEFAULT_P11MODULE_NAME + "' is not defined");
      }
      this.moduleConfs = Collections.unmodifiableMap(confs);
      this.moduleNames = Collections.unmodifiableSet(new HashSet<>(confs.keySet()));
    } catch (RuntimeException ex) {
      throw new InvalidConfException("could not create P11Conf: " + ex.getMessage(), ex);
    }
  } // method init

  public synchronized P11CryptService getP11CryptService(String moduleName)
      throws XiSecurityException, TokenException {
    try {
      init();
    } catch (InvalidConfException ex) {
      throw new IllegalStateException("could not initialize P11CryptServiceFactory: " + ex.getMessage(), ex);
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
  } // method getP11CryptService

  private String getModuleName(String moduleName) {
    return (moduleName == null) ? DEFAULT_P11MODULE_NAME : moduleName;
  }

  public void setPkcs11ConfFile(String confFile) {
    this.pkcs11ConfFile = StringUtil.isBlank(confFile) ? null : IoUtil.expandFilepath(confFile);
    this.pkcs11Conf = null;
  }

  public void setPkcs11Conf(Pkcs11conf conf) throws InvalidConfException {
    if (conf != null) {
      conf.validate();
    }
    this.pkcs11Conf = conf;
    this.pkcs11ConfFile = null;
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
      throw new IllegalStateException("could not initialize P11CryptServiceFactory: " + ex.getMessage(), ex);
    }
    return moduleNames;
  }

}
