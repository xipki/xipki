// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.exception.XiSecurityException;

import java.io.Closeable;
import java.util.Set;

/**
 * Factory to create {@link P11Module}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface P11CryptServiceFactory extends Closeable {

  String DEFAULT_P11MODULE_NAME = "default";

  /**
   * Gets the {@link P11Module} of the given module {@code moduleName}.
   * @param moduleName
   *        Module name. {@code null} for default module name.
   * @return the {@link P11Module} of the given module.
   * @throws TokenException
   *         if PKCS#11 token error occurs.
   * @throws XiSecurityException
   *         if security error occurs.
   */
  P11Module getP11Module(String moduleName)
      throws TokenException, XiSecurityException;

  Set<String> getModuleNames();

}
