// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.SignAlgo;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.EnumCompleter;
import org.xipki.util.CollectionUtil;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Completers for security shells.
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityCompleters {

  @Service
  public static class KeystoreTypeCompleter extends EnumCompleter {

    public KeystoreTypeCompleter() {
      setTokens("PKCS12", "JCEKS");
    }
  } // class KeystoreTypeCompleter

  @Service
  public static class KeystoreTypeWithPEMCompleter extends EnumCompleter {

    public KeystoreTypeWithPEMCompleter() {
      setTokens("PKCS12", "JCEKS", "PEM");
    }
  } // class KeystoreTypeCompleter

  @Service
  public static class P11KeyUsageCompleter extends EnumCompleter {

    public P11KeyUsageCompleter() {
      Set<String> names = new HashSet<>();
      for (P11KeyUsage usage : P11KeyUsage.values()) {
        names.add(usage.name());
      }
      setTokens(names);
    }

    public static Set<P11KeyUsage> parseUsages(List<String> usageTexts) {
      Set<P11KeyUsage> usages = new HashSet<>();
      for (String usageText : usageTexts) {
        P11KeyUsage usage = P11KeyUsage.valueOf(usageText.toUpperCase());
        usages.add(usage);
      }
      return usages;
    }

  } // class P11KeyUsageCompleter

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

  } // class P11ModuleNameCompleter

  @Service
  public static class SecretKeyTypeCompleter extends EnumCompleter {

    public SecretKeyTypeCompleter() {
      setTokens("DES3", "AES", "GENERIC");
    }

  } // class SecretKeyTypeCompleter

  @Service
  public static class SignAlgoCompleter extends EnumCompleter {

    private static final Set<String> algos = new HashSet<>();

    static {
      for (SignAlgo m : SignAlgo.values()) {
        algos.add(m.getJceName());
      }
    }

    public SignAlgoCompleter() {
      setTokens(algos);
    }
  }

}
