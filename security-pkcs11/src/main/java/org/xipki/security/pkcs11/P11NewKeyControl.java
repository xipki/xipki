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

import java.util.HashSet;
import java.util.Set;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class P11NewKeyControl {

  public static enum KeyUsage {
    DECRYPT,
    DERIVE,
    SIGN,
    SIGN_RECOVER,
    UNWRAP
  }

  private Boolean extractable;

  private Set<KeyUsage> usages;

  public Boolean getExtractable() {
    return extractable;
  }

  public void setExtractable(Boolean extractable) {
    this.extractable = extractable;
  }

  public Set<KeyUsage> getUsages() {
    if (usages == null) {
      usages = new HashSet<>();
    }
    return usages;
  }

  public void setUsages(Set<KeyUsage> usages) {
    this.usages = usages;
  }

}
