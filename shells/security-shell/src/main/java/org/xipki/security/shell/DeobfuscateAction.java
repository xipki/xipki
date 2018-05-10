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

package org.xipki.security.shell;

import java.io.File;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.password.OBFPasswordService;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "deobfuscate",
    description = "deobfuscate password")
@Service
public class DeobfuscateAction extends SecurityAction {

  @Option(name = "--password",
      description = "obfuscated password, starts with OBF:\n"
          + "exactly one of password and password-file must be specified")
  private String passwordHint;

  @Option(name = "--password-file", description = "file containing the obfuscated password")
  @Completion(FileCompleter.class)
  private String passwordFile;

  @Option(name = "--out", description = "where to save the password")
  @Completion(FileCompleter.class)
  private String outFile;

  @Override
  protected Object execute0() throws Exception {
    if (!(passwordHint == null ^ passwordFile == null)) {
      throw new IllegalCmdParamException(
          "exactly one of password and password-file must be specified");
    }

    if (passwordHint == null) {
      passwordHint = new String(IoUtil.read(passwordFile));
    }

    if (!StringUtil.startsWithIgnoreCase(passwordHint, "OBF:")) {
      throw new IllegalCmdParamException("encrypted password '" + passwordHint
          + "' does not start with OBF:");
    }

    String password = OBFPasswordService.deobfuscate(passwordHint);
    if (outFile != null) {
      saveVerbose("saved the password to file", new File(outFile),
          new String(password).getBytes());
    } else {
      println("the password is: '" + new String(password) + "'");
    }
    return null;
  }

}
