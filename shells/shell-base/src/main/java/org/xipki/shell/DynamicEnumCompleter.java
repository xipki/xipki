// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.apache.karaf.shell.support.completers.StringsCompleter;

import java.util.List;
import java.util.Set;

/**
 * Completer with dynamic enums.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class DynamicEnumCompleter implements Completer {

  protected abstract Set<String> getEnums();

  @Override
  public int complete(Session session, CommandLine commandLine, List<String> candidates) {
    StringsCompleter delegate = new StringsCompleter();

    for (String s : getEnums()) {
      delegate.getStrings().add(s);
    }

    return delegate.complete(session, commandLine, candidates);
  }

}
