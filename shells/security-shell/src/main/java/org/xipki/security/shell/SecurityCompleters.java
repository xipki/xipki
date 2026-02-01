// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.EnumCompleter;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Completers for security shells.
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityCompleters {

  @Service
  public static class KeySpecCompleter extends EnumCompleter {

    public KeySpecCompleter() {
      KeySpec[] keySpecs = KeySpec.values();
      String[] names = new String[keySpecs.length];
      int i = 0;
      for (KeySpec keySpec : keySpecs) {
        names[i++] = keySpec.name().replace('_', '-');
      }
      setTokens(names);
    }
  } // class KeystoreTypeCompleter

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
      for (NewKeyControl.P11KeyUsage usage
          : NewKeyControl.P11KeyUsage.values()) {
        names.add(usage.name());
      }
      setTokens(names);
    }

    public static Set<NewKeyControl.P11KeyUsage> parseUsages(
        List<String> usageTexts) {
      Set<NewKeyControl.P11KeyUsage> usages = new HashSet<>();
      for (String usageText : usageTexts) {
        NewKeyControl.P11KeyUsage usage =
            NewKeyControl.P11KeyUsage.valueOf(usageText.toUpperCase());
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
      setTokens("DES3", "AES", "SM4", "GENERIC");
    }

  } // class SecretKeyTypeCompleter

  @Service
  public static class SignAlgoCompleter extends EnumCompleter {

    private static final Set<String> algos = new HashSet<>();

    static {
      for (SignAlgo m : SignAlgo.values()) {
        algos.add(m.jceName());
      }
    }

    public SignAlgoCompleter() {
      setTokens(algos);
    }
  }

  @Service
  public static class AllSigAlgCompleter extends EnumCompleter {

    public AllSigAlgCompleter() {
      List<String> algos = new LinkedList<>();
      for (SignAlgo a : SignAlgo.values()) {
        algos.add(a.jceName());
      }
      setTokens(algos);
    }

  } // class SigAlgCompleter

  @Service
  public static class SignerTypeCompleter extends EnumCompleter {

    public SignerTypeCompleter() {
      setTokens("JCEKS", "PKCS11", "PKCS12");
    }

  } // class SignerTypeCompleter

}
