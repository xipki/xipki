// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.XiSecurityException;

import java.io.Closeable;
import java.util.Set;

/**
 * Factory to create {@link P11CryptService}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface P11CryptServiceFactory extends Closeable {

  String DEFAULT_P11MODULE_NAME = "default";

  /**
   * Gets the {@link P11CryptService} of the given module {@code moduleName}.
   * @param moduleName
   *          Module name. {@code null} for default module name.
   * @return the {@link P11CryptService} of the given module.
   * @throws TokenException
   *         if PKCS#11 token error occurs.
   * @throws XiSecurityException
   *         if security error occurs.
   */
  P11CryptService getP11CryptService(String moduleName) throws TokenException, XiSecurityException;

  Set<String> getModuleNames();

}
