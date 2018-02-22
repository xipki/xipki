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
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.password.OBFPasswordService;
import org.xipki.password.PBEAlgo;
import org.xipki.password.PBEPasswordService;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "pbe-enc",
    description = "encrypt password with master password")
@Service
// CHECKSTYLE:SKIP
public class PBEEncryptCmd extends SecurityAction {

  @Option(name = "--iteration-count", aliases = "-n",
      description = "iteration count, between 1 and 65535")
  private int iterationCount = 2000;

  @Option(name = "--out",
      description = "where to save the encrypted password")
  @Completion(FilePathCompleter.class)
  private String outFile;

  @Option(name = "-k",
      description = "quorum of the password parts")
  private Integer quorum = 1;

  @Option(name = "--mpassword-file",
      description = "file containing the (obfuscated) master password")
  @Completion(FilePathCompleter.class)
  private String masterPasswordFile;

  @Option(name = "--mk",
      description = "quorum of the master password parts")
  private Integer mquorum = 1;

  @Override
  protected Object execute0() throws Exception {
    ParamUtil.requireRange("iterationCount", iterationCount, 1, 65535);
    ParamUtil.requireRange("k", quorum, 1, 10);
    ParamUtil.requireRange("mk", mquorum, 1, 10);

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

    char[] password;
    if (quorum == 1) {
      password = readPassword("Password");
    } else {
      char[][] parts = new char[quorum][];
      for (int i = 0; i < quorum; i++) {
        parts[i] = readPassword("Password (part " + (i + 1) + "/" + quorum + ")");
      }
      password = StringUtil.merge(parts);
    }

    String passwordHint = PBEPasswordService.encryptPassword(PBEAlgo.PBEWithHmacSHA256AndAES_256,
        iterationCount, masterPassword, password);
    if (outFile != null) {
      saveVerbose("saved the encrypted password to file", new File(outFile),
          passwordHint.getBytes());
    } else {
      println("the encrypted password is: '" + passwordHint + "'");
    }
    return null;
  }

}
