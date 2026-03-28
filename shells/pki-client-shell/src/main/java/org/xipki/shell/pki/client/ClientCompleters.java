// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.pki.client;

import org.xipki.shell.CompletionProvider;
import org.xipki.shell.security.SecurityRuntime;
import picocli.CommandLine;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Completion providers for security shell commands.
 *
 * @author Lijun Liao (xipki)
 */
public class ClientCompleters {

  public static class P11ModuleNameCompleter implements CompletionProvider {
    @Override
    public Set<String> complete(CommandLine.Model.CommandSpec commandSpec,
                                CommandLine.Model.ArgSpec argSpec, List<String> words,
                                int wordIndex) {
      try {
        return SecurityRuntime.get().p11CryptServiceFactory().getModuleNames();
      } catch (Exception e) {
        return Collections.emptySet();
      }
    }
  }

}
