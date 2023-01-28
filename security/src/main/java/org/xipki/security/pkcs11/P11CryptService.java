/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import static org.xipki.util.Args.notNull;

/**
 * PKCS#11 cryptographic service.
 *
 * @author Lijun Liao
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
