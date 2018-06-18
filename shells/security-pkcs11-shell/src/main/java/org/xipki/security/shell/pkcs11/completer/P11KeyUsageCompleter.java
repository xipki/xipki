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

package org.xipki.security.shell.pkcs11.completer;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.xipki.security.pkcs11.P11NewKeyControl.KeyUsage;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.completer.AbstractEnumCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
public class P11KeyUsageCompleter extends AbstractEnumCompleter {

  public P11KeyUsageCompleter() {
    Set<String> names = new HashSet<>();
    for (KeyUsage usage : KeyUsage.values()) {
      names.add(usage.name());
    }
    setTokens(names);
  }

  public static Set<KeyUsage> parseUsages(List<String> usageTexts)
      throws IllegalCmdParamException {
    Set<KeyUsage> usages = new HashSet<>();
    for (String usageText : usageTexts) {
      KeyUsage usage = KeyUsage.valueOf(usageText.toUpperCase());
      if (usage == null) {
        throw new IllegalCmdParamException("invalid usage " + usageText);
      }
      usages.add(usage);
    }
    return usages;
  }

}
