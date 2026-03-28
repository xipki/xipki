// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.completer;

import org.xipki.shell.CompletionProvider;
import picocli.CommandLine;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Abstract Set Completer
 *
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractSetCompleter implements CompletionProvider {

  private Set<String> values;

  protected void setTokens(String... values) {
    this.values = new HashSet<>(Arrays.asList(values));
  }

  protected void setTokens(Set<String> values) {
    this.values = values;
  }

  protected void setTokens(Enum<?>[] enums) {
    this.values = new HashSet<>();
    for (Enum<?> m : enums) {
      this.values.add(m.name());
    }
  }

  @Override
  public Set<String> complete(
      CommandLine.Model.CommandSpec commandSpec, CommandLine.Model.ArgSpec argSpec,
      List<String> words, int wordIndex) {
    return values == null ? Collections.emptySet() : values;
  }

}
