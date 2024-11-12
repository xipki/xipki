// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.util.Args;

/**
 * PKCS#11 cryptographic service.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11CryptService {

  private final P11Module module;

  public P11CryptService(P11Module module) {
    this.module = Args.notNull(module, "module");
  }

  public P11Module getModule() {
    return module;
  }

  @Override
  public String toString() {
    return module.toString();
  }

}
