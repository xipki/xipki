// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Locale;

/**
 * Callback to get password.
 *
 * @author Lijun Liao (xipki)
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
  void init(String conf) throws PasswordResolverException;

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
  char[] getPassword(String prompt, String testToken) throws PasswordResolverException;

  class File implements PasswordCallback {

    private String passwordFile;

    @Override
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
      if (passwordFile == null) {
        throw new PasswordResolverException("please initialize me first");
      }

      String passwordHint = null;
      try (BufferedReader reader = Files.newBufferedReader(Paths.get(passwordFile))) {
        String line;
        while ((line = reader.readLine()) != null) {
          line = line.trim();
          if (Args.isNotBlank(line) && !line.startsWith("#")) {
            passwordHint = line;
            break;
          }
        }
      } catch (IOException ex) {
        throw new PasswordResolverException("could not read file " + passwordFile, ex);
      }

      if (passwordHint == null) {
        throw new PasswordResolverException("no password is specified in file " + passwordFile);
      }

      if (Args.startsWithIgnoreCase(passwordHint, OBFPasswordService.PROTOCOL_OBF + ":")) {
        return OBFPasswordService.deobfuscate(passwordHint).toCharArray();
      } else {
        return passwordHint.toCharArray();
      }
    } // method getPassword

    @Override
    public void init(String conf) throws PasswordResolverException {
      Args.notBlank(conf, "conf");
      ConfPairs pairs = new ConfPairs(conf);
      passwordFile = pairs.value("file");
      if (Args.isBlank(passwordFile)) {
        throw new PasswordResolverException("invalid configuration " + conf + ", no file is specified");
      }
    }

  }

  class Gui implements PasswordCallback {

    private int quorum = 1;

    private int tries = 3;

    protected boolean isPasswordValid(char[] password, String testToken) {
      return true;
    }

    @Override
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
      String tmpPrompt = prompt;
      if (Args.isBlank(tmpPrompt)) {
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
          password = Args.merge(passwordParts);
        }

        if (isPasswordValid(password, testToken)) {
          return password;
        }
      }

      throw new PasswordResolverException("Could not get the password after " + tries + " tries");
    }

    @Override
    public void init(String conf) throws PasswordResolverException {
      if (Args.isBlank(conf)) {
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
      if (Args.isNotBlank(str)) {
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
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
      if (password == null) {
        throw new PasswordResolverException("please initialize me first");
      }

      return password;
    }

    @Override
    public void init(String conf) throws PasswordResolverException {
      Args.notBlank(conf, "conf");
      this.password = OBFPasswordService.deobfuscate(conf).toCharArray();
    }

  }

  class PBEGui extends Gui {

    @Override
    protected boolean isPasswordValid(char[] password, String testToken) {
      if (Args.isBlank(testToken)) {
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

  static PasswordCallback getInstance(String passwordCallback) {
    String type;
    String conf = null;

    int delimIndex = passwordCallback.indexOf(' ');
    if (delimIndex == -1) {
      type = passwordCallback;
    } else {
      type = passwordCallback.substring(0, delimIndex);
      conf = passwordCallback.substring(delimIndex + 1);
    }

    PasswordCallback pwdCallback;
    switch (type.toUpperCase(Locale.ROOT)) {
      case "FILE":
        pwdCallback = new PasswordCallback.File();
        break;
      case "GUI":
        pwdCallback = new PasswordCallback.Gui();
        break;
      case "PBE-GUI":
        pwdCallback = new PasswordCallback.PBEGui();
        break;
      case OBFPasswordService.PROTOCOL_OBF:
        pwdCallback = new PasswordCallback.OBF();
        if (conf != null && !Args.startsWithIgnoreCase(conf, OBFPasswordService.PROTOCOL_OBF + ":")) {
          conf = OBFPasswordService.PROTOCOL_OBF + ":" + conf;
        }
        break;
      default:
        String callbackClass = type;
        try {
          pwdCallback = (PasswordCallback) PasswordCallback.class.getClassLoader()
              .loadClass(callbackClass).getConstructor().newInstance();
        } catch (Exception e) {
          throw new IllegalStateException("unknown PasswordCallback type '" + type + "'");
        }
    }

    try {
      pwdCallback.init(conf);
    } catch (PasswordResolverException ex) {
      throw new IllegalArgumentException("invalid passwordCallback configuration "
          + passwordCallback + ", " + ex.getClass().getName() + ": " + ex.getMessage());
    }

    return pwdCallback;
  }

}
