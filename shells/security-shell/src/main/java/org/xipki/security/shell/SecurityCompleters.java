/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.security.shell;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.EnumCompleter;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.CollectionUtil;

/**
 * Completers for security shells.
 *
 * @author Lijun Liao
 */
public class SecurityCompleters {

  @Service
  public static class KeystoreTypeCompleter extends EnumCompleter {

    public KeystoreTypeCompleter() {
      setTokens("PKCS12", "JKS", "JCEKS");
    }
  }

  @Service
  public static class P11KeyUsageCompleter extends EnumCompleter {

    public P11KeyUsageCompleter() {
      Set<String> names = new HashSet<>();
      for (P11KeyUsage usage : P11KeyUsage.values()) {
        names.add(usage.name());
      }
      setTokens(names);
    }

    public static Set<P11KeyUsage> parseUsages(List<String> usageTexts)
        throws IllegalCmdParamException {
      Set<P11KeyUsage> usages = new HashSet<>();
      for (String usageText : usageTexts) {
        P11KeyUsage usage = P11KeyUsage.valueOf(usageText.toUpperCase());
        if (usage == null) {
          throw new IllegalCmdParamException("invalid usage " + usageText);
        }
        usages.add(usage);
      }
      return usages;
    }

  }

  @Service
  public static class P11ModuleNameCompleter extends DynamicEnumCompleter {

    @Reference (optional = true)
    private P11CryptServiceFactory p11CryptServiceFactory;

    @Override
    protected Set<String> getEnums() {
      Set<String> names = p11CryptServiceFactory.getModuleNames();
      if (CollectionUtil.isEmpty(names)) {
        return Collections.emptySet();
      }
      return names;
    }

  }

  @Service
  public static class SecretKeyTypeCompleter extends EnumCompleter {

    public SecretKeyTypeCompleter() {
      setTokens("DES3", "AES", "GENERIC");
    }

  }

}
