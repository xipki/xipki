// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.security.KeySpec;
import org.xipki.shell.CompletionProvider;
import org.xipki.shell.completer.AbstractSetCompleter;
import picocli.CommandLine;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Completion providers for security shell commands.
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityCompleters {

  public static class KeySpecCompleter extends AbstractSetCompleter {
    public KeySpecCompleter() {
      setTokens(KeySpec.values());
    }
  }

  public static class P11KeyUsageCompleter extends AbstractSetCompleter {
    public P11KeyUsageCompleter() {
      setTokens(NewKeyControl.P11KeyUsage.values());
    }
  }

  public static class KeystoreTypeCompleter extends AbstractSetCompleter {
    public KeystoreTypeCompleter() {
      setTokens("PKCS12", "JCEKS");
    }
  }

  public static class KeystoreTypeWithPEMCompleter extends AbstractSetCompleter {
    public KeystoreTypeWithPEMCompleter() {
      setTokens("PKCS12", "JCEKS", "PEM");
    }
  }

  public static class P11ModuleNameCompleter implements CompletionProvider {
    @Override
    public Set<String> complete(
        CommandLine.Model.CommandSpec commandSpec, CommandLine.Model.ArgSpec argSpec,
        List<String> words, int wordIndex) {
      try {
        return SecurityRuntime.get().p11CryptServiceFactory().getModuleNames();
      } catch (Exception e) {
        return Collections.emptySet();
      }
    }
  }

  public static class SecretKeyTypeCompleter extends AbstractSetCompleter {
    public SecretKeyTypeCompleter() {
      setTokens("DES3", "AES", "SM4", "GENERIC");
    }
  }

}
