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

import java.io.Closeable;
import java.util.Set;

import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.exception.P11TokenException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface P11CryptServiceFactory extends Closeable {

  String DEFAULT_P11MODULE_NAME = "default";

  /**
   * Gets the {@link P11CryptService} of the given module {@code moduleName}.
   * @param moduleName
   *          Module name. Must not be {@code null}.
   * @return the {@link P11CryptService} of the given module.
   * @throws P11TokenException
   *         if PKCS#11 token error occurs.
   * @throws XiSecurityException
   *         if security error occurs.
   */
  P11CryptService getP11CryptService(String moduleName)
      throws P11TokenException, XiSecurityException;

  Set<String> getModuleNames();

  @Deprecated
  void shutdown();

}
