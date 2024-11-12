// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.hsmproxy;

import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11ModuleConf;
import org.xipki.security.pkcs11.P11ModuleFactory;
import org.xipki.util.XipkiBaseDir;

/**
 * {@link P11ModuleFactory} to create {@link P11Module} of type "hsmproxy".
 *
 * @author Lijun Liao (xipki)
 *
 */
public class HsmProxyP11ModuleFactory implements P11ModuleFactory {

  public HsmProxyP11ModuleFactory() {
    XipkiBaseDir.init();
  }

  @Override
  public boolean canCreateModule(String type) {
    return HsmProxyP11Module.TYPE.equalsIgnoreCase(type);
  }

  @Override
  public P11Module newModule(P11ModuleConf conf) throws TokenException {
    return HsmProxyP11Module.getInstance(conf);
  }

}
