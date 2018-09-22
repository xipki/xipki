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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.password.OBFPasswordService;
import org.xipki.password.PBEPasswordService;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "pbe-dec", description = "decrypt password with master password")
@Service
// CHECKSTYLE:SKIP
public class PBEDecryptAction extends SecurityAction {

  @Option(name = "--password",
      description = "encrypted password, starts with PBE:\n"
          + "exactly one of password and password-file must be specified")
  private String passwordHint;

  @Option(name = "--password-file", description = "file containing the encrypted password")
  @Completion(FileCompleter.class)
  private String passwordFile;

  @Option(name = "--mpassword-file",
      description = "file containing the (obfuscated) master password")
  @Completion(FileCompleter.class)
  private String masterPasswordFile;

  @Option(name = "--mk", description = "quorum of the master password parts")
  private Integer mquorum = 1;

  @Option(name = "--out", description = "where to save the password")
  @Completion(FileCompleter.class)
  private String outFile;

  @Override
  protected Object execute0() throws Exception {
    ParamUtil.requireRange("mk", mquorum, 1, 10);
    if (!(passwordHint == null ^ passwordFile == null)) {
      throw new IllegalCmdParamException(
          "exactly one of password and password-file must be specified");
    }

    if (passwordHint == null) {
      passwordHint = new String(IoUtil.read(passwordFile));
    }

    if (!StringUtil.startsWithIgnoreCase(passwordHint, "PBE:")) {
      throw new IllegalCmdParamException("encrypted password '" + passwordHint
          + "' does not start with PBE:");
    }

    char[] masterPassword;
    if (masterPasswordFile != null) {
      String str = new String(IoUtil.read(masterPasswordFile));
      if (str.startsWith("OBF:") || str.startsWith("obf:")) {
        str = OBFPasswordService.deobfuscate(str);
      }
      masterPassword = str.toCharArray();
    } else {
      if (mquorum == 1) {
        masterPassword = readPassword("Master password");
      } else {
        char[][] parts = new char[mquorum][];
        for (int i = 0; i < mquorum; i++) {
          parts[i] = readPassword("Master password (part " + (i + 1) + "/" + mquorum + ")");
        }
        masterPassword = StringUtil.merge(parts);
      }
    }
    char[] password = PBEPasswordService.decryptPassword(masterPassword, passwordHint);

    if (outFile != null) {
      saveVerbose("saved the password to file", outFile, new String(password).getBytes());
    } else {
      println("the password is: '" + new String(password) + "'");
    }
    return null;
  }

}
