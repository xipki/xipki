// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.apache.karaf.shell.api.action.Action;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.console.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.password.SecurePasswordInputPanel;
import org.xipki.util.*;
import org.xipki.util.PemEncoder.PemLabel;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Collection;
import java.util.List;

/**
 * Anchor class for all actions. All actions should derive from this one.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public abstract class XiAction implements Action {

  private static final Logger LOG = LoggerFactory.getLogger(XiAction.class);

  @Reference
  protected Session session;

  @Reference
  protected PasswordResolver passwordResolver;

  protected char[] resolvePassword(String passwordHint) throws PasswordResolverException {
    return passwordResolver.resolvePassword(passwordHint);
  }

  protected abstract Object execute0() throws Exception;

  @Override
  public Object execute() throws Exception {
    return execute0();
  }

  protected boolean isTrue(Boolean bo) {
    return bo != null && bo;
  }

  protected ConfPairs embedFileContent(ConfPairs confPairs) throws IOException {
    boolean changed = false;
    for (String name : confPairs.names()) {
      String value = confPairs.value(name);
      if (value.startsWith("file:")) {
        changed = true;
        break;
      }
    }

    if (!changed) {
      return confPairs;
    }

    ConfPairs newPairs = new ConfPairs();
    for (String name : confPairs.names()) {
      String value = confPairs.value(name);
      if (value.startsWith("file:")) {
        String fileName = value.substring("file:".length());
        byte[] binValue = IoUtil.read(fileName);
        confPairs.putPair(name, "base64:" + Base64.encodeToString(binValue));
      } else {
        newPairs.putPair(name, value);
      }
    }

    return newPairs;
  } // method embedFileContent

  protected void saveVerbose(String promptPrefix, String file, byte[] encoded) throws IOException {
    saveVerbose(promptPrefix, new File(file), encoded);
  }

  protected void saveVerbose(String promptPrefix, File file, byte[] encoded) throws IOException {
    File saveTo = expandFilepath(file);

    if (saveTo.exists()) {
      try {
        boolean bo = true;
        while (saveTo.exists()) {
          String answer;
          if (bo) {
            answer = readPrompt("A file named '" + saveTo.getPath()
              + "' already exists. Do you want to replace it [Yes/No]? ");
          } else {
            answer = readPrompt("Please answer with Yer or No: ");
          }

          if (answer == null) {
            throw new IOException("interrupted");
          }

          if (StringUtil.orEqualsIgnoreCase(answer, "yes", "y")) {
            break;
          } else if (StringUtil.orEqualsIgnoreCase(answer, "no", "n")) {
            bo = true;
            String newFn;
            while (true) {
              newFn = readPrompt("Enter new path to save to ... ");
              if (!newFn.trim().isEmpty()) {
                break;
              }
            }

            saveTo = new File(newFn);
          } else {
            bo = false;
          }
        } // end while
      } catch (IOException ex) {
        LogUtil.error(LOG, ex, "could not save file");
        saveTo = new File("tmp-" + randomHex(6));
      }
    } // end if(saveTo.exists())

    int tries = 2;
    while (true) {
      try {
        tries--;
        save(saveTo, encoded);
        break;
      } catch (IOException ex) {
        println("ERROR: " + ex.getMessage());
        if (tries > 0) {
          String newFn;
          while (true) {
            newFn = readPrompt("Enter new path to save to ... ");
            if (!newFn.trim().isEmpty()) {
              break;
            }
          }
          saveTo = new File(newFn);
        } else if (tries == 0) {
          // save it to tmp file
          saveTo = new File("tmp-" + randomHex(6));
        } else {
          LogUtil.error(LOG, ex, "could not save to file");
          throw new IOException("could not save to file", ex);
        }
      }
    }

    String tmpPromptPrefix = promptPrefix;
    if (promptPrefix == null || promptPrefix.isEmpty()) {
      tmpPromptPrefix = "saved to file";
    }

    println(tmpPromptPrefix + " " + saveTo.getPath());
  } // method saveVerbose

  protected void save(String file, byte[] encoded) throws IOException {
    save(new File(file), encoded);
  }

  protected void save(File file, byte[] encoded) throws IOException {
    File tmpFile = expandFilepath(file);
    File parent = tmpFile.getParentFile();
    if (parent != null) {
      if (parent.exists()) {
        if (!parent.isDirectory()) {
          throw new IOException("The path " + parent.getPath() + " is not a directory.");
        }
      } else {
        parent.mkdirs();
      }
    }

    Files.copy(
        new ByteArrayInputStream(encoded), tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
  } // method save

  private static String randomHex(int numOfBytes) {
    return Hex.encode(RandomUtil.nextBytes(numOfBytes));
  }

  protected static boolean isEnabled(String enabledS, boolean defaultEnabled, String optionName) {
    return (enabledS == null) ? defaultEnabled : isEnabled(enabledS, optionName);
  }

  private static boolean isEnabled(String enabledS, String optionName) {
    if (StringUtil.orEqualsIgnoreCase(enabledS, "yes", "enabled", "true")) {
      return true;
    } else if (StringUtil.orEqualsIgnoreCase(enabledS, "no", "disabled", "false")) {
      return false;
    } else {
      throw new IllegalArgumentException("invalid option " + optionName + ": " + enabledS);
    }
  }

  protected String readPrompt(String prompt) throws IOException {
    String tmpPrompt = prompt;
    if (StringUtil.isNotBlank(prompt)) {
      if (!prompt.endsWith(" ")) {
        tmpPrompt += " ";
      }
    }
    return readLine(tmpPrompt, null);
  }

  protected char[] readPasswordIfNotSet(String password) throws IOException, PasswordResolverException {
    return readPasswordIfNotSet(null, password);
  }

  protected char[] readPasswordIfNotSet(String prompt, String password) throws IOException, PasswordResolverException {
    return (password != null) ? resolvePassword(password) : readPassword(prompt);
  }

  protected char[] readPassword() throws IOException, PasswordResolverException {
    return readPassword(null);
  }

  protected char[] readPassword(String prompt) throws IOException, PasswordResolverException {
    String tmpPrompt = (prompt == null) ? "Password:" : prompt.trim();

    if (!tmpPrompt.endsWith(":")) {
      tmpPrompt += ":";
    }

    String passwordUi = System.getProperty("org.xipki.console.passwordui");
    char[] pwd = "gui".equalsIgnoreCase(passwordUi)
              ? SecurePasswordInputPanel.readPassword(tmpPrompt) : readLine(tmpPrompt, '*').toCharArray();
    if (pwd == null || pwd.length == 0) {
      return pwd;
    } else {
      return passwordResolver.resolvePassword(new String(pwd));
    }
  }

  private String readLine(String prompt, Character ch) throws IOException {
    Object oldIgnoreInterrupts = session.get(Session.IGNORE_INTERRUPTS);
    session.put(Session.IGNORE_INTERRUPTS, Boolean.TRUE);
    try {
      String line = session.readLine(prompt, ch);
      if (line == null) {
        throw new IOException("interrupted");
      }
      return line;
    } finally {
      session.put(Session.IGNORE_INTERRUPTS, oldIgnoreInterrupts);
    }
  }

  protected static String expandFilepath(String path) {
    return IoUtil.expandFilepath(path);
  }

  protected static File expandFilepath(File file) {
    return IoUtil.expandFilepath(file);
  }

  protected void println(String message) {
    System.out.println(message);
  }

  protected void print(String message) {
    System.out.print(message);
  }

  protected static boolean isBlank(String str) {
    return StringUtil.isBlank(str);
  }

  protected static boolean isNotBlank(String str) {
    return StringUtil.isNotBlank(str);
  }

  protected static boolean isEmpty(Collection<?> col) {
    return CollectionUtil.isEmpty(col);
  }

  protected static boolean isNotEmpty(Collection<?> col) {
    return CollectionUtil.isNotEmpty(col);
  }

  protected static List<String> split(String str, String delim) {
    return StringUtil.split(str, delim);
  }

  protected static BigInteger toBigInt(String str) {
    return toBigInt(str, false);
  }

  protected static BigInteger toBigInt(String str, boolean defaultHex) {
    return StringUtil.toBigInt(str, defaultHex);
  }

  protected static byte[] encodeCert(byte[] data, String encodeForm) {
    return derPemEncode(data, encodeForm, PemLabel.CERTIFICATE);
  }

  protected static byte[] encodeCrl(byte[] data, String encodeForm) {
    return derPemEncode(data, encodeForm, PemLabel.X509_CRL);
  }

  protected static byte[] encodeCsr(byte[] data, String encodeForm) {
    return derPemEncode(data, encodeForm, PemLabel.CERTIFICATE_REQUEST);
  }

  protected static byte[] derPemEncode(byte[] data, String encodeForm, PemLabel pemLabel) {
    return "pem".equalsIgnoreCase(encodeForm) ? PemEncoder.encode(data, pemLabel) : data;
  }

  protected boolean confirm(String prompt, int maxTries) throws IOException {
    String tmpPrompt;
    if (prompt == null || prompt.isEmpty()) {
      tmpPrompt = "(Yes/No)? ";
    } else {
      tmpPrompt = ('?' == prompt.charAt(prompt.length() - 1)) ? prompt.substring(0, prompt.length() - 1) : prompt;
      tmpPrompt += " (Yes/No)? ";
    }

    String answer = readLine(tmpPrompt, null);

    int tries = 1;

    while (tries <= maxTries) {
      if (StringUtil.orEqualsIgnoreCase(answer, "yes", "y")) {
        return true;
      } else if (StringUtil.orEqualsIgnoreCase(answer, "no", "n")) {
        return false;
      } else {
        tries++;
      }
      answer = readLine("Please answer with Yes or No: ", null);
    }

    return false;
  } // method confirm

}
