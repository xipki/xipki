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

package org.xipki.shell;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.apache.karaf.shell.support.completers.StringsCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class EnumCompleter implements Completer {

  private final List<String> enums = new LinkedList<>();

  protected void setTokens(Collection<? extends Object> tokens) {
    enums.clear();
    for (Object token : tokens) {
      enums.add(token.toString());
    }
  }

  protected void setTokens(String... a) {
    setTokens(Arrays.asList(a));
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
