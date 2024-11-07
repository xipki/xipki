// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.emulator;

import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11ModuleConf;
import org.xipki.security.pkcs11.P11ModuleFactory;

/**
 * {@link P11ModuleFactory} to create {@link P11Module} of type "emulator".
 *
 * @author Lijun Liao (xipki)
 *
 */
public class EmulatorP11ModuleFactory implements P11ModuleFactory {

  public EmulatorP11ModuleFactory() {
  }

  @Override
  public boolean canCreateModule(String type) {
    return EmulatorP11Module.TYPE.equalsIgnoreCase(type);
  }

  @Override
  public P11Module newModule(P11ModuleConf conf) throws TokenException {
    return EmulatorP11Module.getInstance(conf);
  }

}
