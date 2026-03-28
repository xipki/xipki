// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.CommandSpec;

import java.util.List;
import java.util.Set;

/**
 * Interface for providing explicit completion candidates dynamically based on contextual input.
 *
 * @author Lijun Liao (xipki)
 */
public interface CompletionProvider {

  /**
   * Complete the currently typed input word with candidates.
   *
   * @param commandSpec the command parsing specification
   * @param argSpec the specific argument or option specification
   * @param words the currently typed input words on the exact command line
   * @param wordIndex the index of the word currently being typed
   * @return a set of matching candidates, or null/empty if none
   */
  Set<String> complete(CommandSpec commandSpec, ArgSpec argSpec, List<String> words, int wordIndex);

}
