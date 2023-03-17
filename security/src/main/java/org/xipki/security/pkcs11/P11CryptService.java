// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import static org.xipki.util.Args.notNull;

/**
 * PKCS#11 cryptographic service.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11CryptService {

  private final P11Module module;

  public P11CryptService(P11Module module) {
    this.module = notNull(module, "module");
  }

  public P11Module getModule() {
    return module;
  }

  @Override
  public String toString() {
    return module.toString();
  }

}
