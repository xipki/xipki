// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.XiSecurityException;
import org.xipki.util.IoUtil;
import org.xipki.util.JSON;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * An implementation of {@link P11CryptServiceFactory}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11CryptServiceFactoryImpl implements P11CryptServiceFactory {

  private static final Logger LOG = LoggerFactory.getLogger(P11CryptServiceFactoryImpl.class);

  private P11CryptService service;

  private P11ModuleConf moduleConf;

  private String pkcs11ConfFile;

  private Pkcs11conf pkcs11Conf;

  private final P11ModuleFactoryRegister p11ModuleFactoryRegister;

  public P11CryptServiceFactoryImpl(P11ModuleFactoryRegister p11ModuleFactoryRegister) {
    this.p11ModuleFactoryRegister = p11ModuleFactoryRegister;
  }

  public synchronized void init() throws InvalidConfException {
    if (moduleConf != null) {
      return;
    }

    if (pkcs11Conf == null && StringUtil.isBlank(pkcs11ConfFile)) {
      LOG.error("neither pkcs11Conf nor pkcs11ConfFile is configured, could not initialize");
      return;
    }

    if (pkcs11Conf == null) {
      try {
        pkcs11Conf = JSON.parseConf(new File(pkcs11ConfFile), Pkcs11conf.class);
        pkcs11Conf.validate();
      } catch (IOException ex) {
        throw new InvalidConfException("could not create P11Conf: " + ex.getMessage(), ex);
      }
    }

    this.moduleConf = new P11ModuleConf(pkcs11Conf);
  } // method init

  @Override
  public synchronized P11CryptService getP11CryptService()
      throws TokenException {
    try {
      init();
    } catch (InvalidConfException ex) {
      throw new IllegalStateException("could not initialize P11CryptServiceFactory: " + ex.getMessage(), ex);
    }

    if (moduleConf == null) {
      throw new IllegalStateException("please set pkcs11ConfFile and then call init() first");
    }

    if (service == null) {
      P11Module p11Module = p11ModuleFactoryRegister.getP11Module(moduleConf);
      service = new P11CryptService(p11Module);
      LOG.info("initialized PKCS#11 module \n{}", service.getModule().getDescription());
    }

    return service;
  } // method getP11CryptService

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

  @Override
  public void close() {
  }

}
