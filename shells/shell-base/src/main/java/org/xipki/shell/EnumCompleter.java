// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.apache.karaf.shell.support.completers.StringsCompleter;

import java.util.*;

/**
 * Completer with static enums.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class EnumCompleter implements Completer {

  private final List<String> enums = new LinkedList<>();

  protected void setTokens(Collection<?> tokens) {
    enums.clear();
    for (Object token : tokens) {
      enums.add(token.toString());
    }
  }

  protected void setTokens(String... a) {
    setTokens(Arrays.asList(a));
  }

  public List<String> enums() {
    return Collections.unmodifiableList(enums);
  }

  @Override
  public int complete(Session session, CommandLine commandLine, List<String> candidates) {
    StringsCompleter delegate = new StringsCompleter();
    for (String entry : enums) {
      delegate.getStrings().add(entry);
    }
    return delegate.complete(session, commandLine, candidates);
  }

}
