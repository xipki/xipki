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
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.OBFPasswordService;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "obfuscate",
    description = "obfuscate password")
@Service
public class ObfuscateAction extends SecurityAction {

  @Option(name = "--out",
      description = "where to save the encrypted password")
  @Completion(FileCompleter.class)
  private String outFile;

  @Option(name = "-k",
      description = "quorum of the password parts")
  private Integer quorum = 1;

  @Override
  protected Object execute0() throws Exception {
    ParamUtil.requireRange("k", quorum, 1, 10);

    char[] password;
    if (quorum == 1) {
      password = readPassword("Password");
    } else {
      char[][] parts = new char[quorum][];
      for (int i = 0; i < quorum; i++) {
        parts[i] = readPassword("Password " + (i + 1) + "/" + quorum);
      }
      password = StringUtil.merge(parts);
    }

    String passwordHint = OBFPasswordService.obfuscate(new String(password));
    if (outFile != null) {
      saveVerbose("saved the obfuscated password to file", new File(outFile),
          passwordHint.getBytes());
    } else {
      println("the obfuscated password is: '" + passwordHint + "'");
    }
    return null;
  }

}
