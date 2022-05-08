/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Callback to get password.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface PasswordCallback {

  /**
   * Initializes me.
   *
   * @param conf
   *          Configuration. Could be {@code null}.
   * @throws PasswordResolverException
   *         if error occurs
   */
  void init(String conf)
      throws PasswordResolverException;

  /**
   * Resolves the password
   * @param prompt
   *          Prompt shown to use while asking password. Could be {@code null}.
   * @param testToken
   *          Token used to test whether the retrieved password is correct. Could be {@code null}.
   * @return the resolved password
   * @throws PasswordResolverException
   *         if error occurs
   */
  char[] getPassword(String prompt, String testToken)
      throws PasswordResolverException;

  class File implements PasswordCallback {

    private static final Logger LOG = LoggerFactory.getLogger(File.class);

    private String passwordFile;

    @Override
    public char[] getPassword(String prompt, String testToken)
        throws PasswordResolverException {
      if (passwordFile == null) {
        throw new PasswordResolverException("please initialize me first");
      }

      passwordFile = IoUtil.detectPath(passwordFile);

      String passwordHint = null;
      BufferedReader reader = null;
      try {
        reader = Files.newBufferedReader(Paths.get(passwordFile));
        String line;
        while ((line = reader.readLine()) != null) {
          line = line.trim();
          if (StringUtil.isNotBlank(line) && !line.startsWith("#")) {
            passwordHint = line;
            break;
          }
        }
      } catch (IOException ex) {
        throw new PasswordResolverException("could not read file " + passwordFile, ex);
      } finally {
        if (reader != null) {
          try {
            reader.close();
          } catch (IOException ex) {
            LOG.error("could not close reader: {}", ex.getMessage());
          }
        }
      }

      if (passwordHint == null) {
        throw new PasswordResolverException("no password is specified in file " + passwordFile);
      }

      if (StringUtil.startsWithIgnoreCase(passwordHint, OBFPasswordService.OBFUSCATE)) {
        return OBFPasswordService.deobfuscate(passwordHint).toCharArray();
      } else {
        return passwordHint.toCharArray();
      }
    } // method getPassword

    @Override
    public void init(String conf)
        throws PasswordResolverException {
      Args.notBlank(conf, "conf");
      ConfPairs pairs = new ConfPairs(conf);
      passwordFile = pairs.value("file");
      if (StringUtil.isBlank(passwordFile)) {
        throw new PasswordResolverException("invalid configuration " + conf
            + ", no file is specified");
      }
      passwordFile = IoUtil.expandFilepath(passwordFile);
    }

  }

  class Gui implements PasswordCallback {

    private int quorum = 1;

    private int tries = 3;

    protected boolean isPasswordValid(char[] password, String testToken) {
      return true;
    }

    @Override
    public char[] getPassword(String prompt, String testToken)
        throws PasswordResolverException {
      String tmpPrompt = prompt;
      if (StringUtil.isBlank(tmpPrompt)) {
        tmpPrompt = "Password required";
      }

      for (int i = 0; i < tries; i++) {
        char[] password;
        if (quorum == 1) {
          password = SecurePasswordInputPanel.readPassword(tmpPrompt);
          if (password == null) {
            throw new PasswordResolverException("user has cancelled");
          }
        } else {
          char[][] passwordParts = new char[quorum][];
          for (int j = 0; j < quorum; j++) {
            String promptPart = tmpPrompt + " (part " + (j + 1) + "/" + quorum + ")";
            passwordParts[j] = SecurePasswordInputPanel.readPassword(promptPart);
            if (passwordParts[j] == null) {
              throw new PasswordResolverException("user has cancelled");
            }
          }
          password = StringUtil.merge(passwordParts);
        }

        if (isPasswordValid(password, testToken)) {
          return password;
        }
      }

      throw new PasswordResolverException("Could not get the password after " + tries + " tries");
    }

    @Override
    public void init(String conf)
        throws PasswordResolverException {
      if (StringUtil.isBlank(conf)) {
        quorum = 1;
        return;
      }

      ConfPairs pairs = new ConfPairs(conf);
      String str = pairs.value("quorum");
      quorum = Integer.parseInt(str);
      if (quorum < 1 || quorum > 10) {
        throw new PasswordResolverException("quorum " + quorum + " is not in [1,10]");
      }

      str = pairs.value("tries");
      if (StringUtil.isNotBlank(str)) {
        int intValue = Integer.parseInt(str);
        if (intValue > 0) {
          this.tries = intValue;
        }
      }
    }

  }

  class OBF implements PasswordCallback {

    private char[] password;

    @Override
    public char[] getPassword(String prompt, String testToken)
        throws PasswordResolverException {
      if (password == null) {
        throw new PasswordResolverException("please initialize me first");
      }

      return password;
    }

    @Override
    public void init(String conf)
        throws PasswordResolverException {
      Args.notBlank(conf, "conf");
      this.password = OBFPasswordService.deobfuscate(conf).toCharArray();
    }

  }

  class PBEGui extends Gui {

    @Override
    protected boolean isPasswordValid(char[] password, String testToken) {
      if (StringUtil.isBlank(testToken)) {
        return true;
      }
      try {
        PBEPasswordService.decryptPassword(password, testToken);
        return true;
      } catch (PasswordResolverException ex) {
        return false;
      }
    }

  }

}
