// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.SignAlgo;
import org.xipki.shell.EnumCompleter;

import java.util.HashSet;
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
