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

package org.xipki.console.karaf.command;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.XiAction;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "confirm",
    description = "confirm an action")
@Service
public class ConfirmAction extends XiAction {

  @Argument(index = 0, name = "message", required = true,
      description = "prompt message\n(required)")
  private String prompt;

  @Override
  protected Object execute0() throws Exception {
    boolean toContinue = confirm(prompt + "\nDo you want to continue", 3);
    if (!toContinue) {
      throw new CmdFailure("User cancelled");
    }

    return null;
  }

}
