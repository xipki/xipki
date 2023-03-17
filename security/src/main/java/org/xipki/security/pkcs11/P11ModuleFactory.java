// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.TokenException;

/**
 * Factory to create {@link P11Module}.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public interface P11ModuleFactory {

  /**
   * Indicates whether a PKCS#11 module of the given {@code type} can be created or not.
   *
   * @param type
   *          Type of the signer. Must not be {@code null}.
   * @return true if PKCS#11 module of the given type can be created, false otherwise.
   */
  boolean canCreateModule(String type);

  /**
   * Creates a new signer.
   * @param conf
   *          Configuration of the PKCS#11 module. Must not be {@code null}.
   *
   * @return new PKCS#11 module.
   * @throws TokenException
   *         if PKCS#11 module could not be created.
   */
  P11Module newModule(P11ModuleConf conf) throws TokenException;

}
