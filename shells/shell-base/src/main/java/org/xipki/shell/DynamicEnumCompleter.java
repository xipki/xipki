/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.apache.karaf.shell.support.completers.StringsCompleter;

/**
 * TODO.
 * @author Lijun Liao
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
