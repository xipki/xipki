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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;

import org.apache.karaf.shell.api.action.Action;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.console.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.SecurePasswordInputPanel;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.Hex;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.PemEncoder;
import org.xipki.util.PemEncoder.PemLabel;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public abstract class XiAction implements Action {

  private static final Logger LOG = LoggerFactory.getLogger(XiAction.class);

  @Reference
  protected Session session;

  protected abstract Object execute0() throws Exception;

  @Override
  public Object execute() throws Exception {
    return execute0();
  }

  protected boolean isTrue(Boolean bo) {
    return bo != null && bo.booleanValue();
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
  }

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
              + "' already exists. Do you want to replace it [yes/no]? ");
          } else {
            answer = session.readLine(null, null);
          }

          if (answer == null) {
            throw new IOException("interrupted");
          }

          if ("yes".equalsIgnoreCase(answer)) {
            break;
          } else if ("no".equalsIgnoreCase(answer)) {
            String newFn;
            while (true) {
              newFn = readPrompt("Enter new path to save to ... ");
              if (!newFn.trim().isEmpty()) {
                break;
              }
            }

            saveTo = new File(newFn);
          } else {
            readPrompt("Please answer with yes or no. ");
            bo = false;
          }
        } // end while
      } catch (IOException ex) {
        LogUtil.error(LOG, ex, "could not save file");
        saveTo = new File("tmp-" + randomHex(6));
      }
    } // end if(saveTo.exists())

    int retries = 2;
    while (true) {
      try {
        save(saveTo, encoded);
        break;
      } catch (IOException ex) {
        println("ERROR: " + ex.getMessage());
        if (retries > 0) {
          String newFn;
          while (true) {
            newFn = readPrompt("Enter new path to save to ... ");
            if (!newFn.trim().isEmpty()) {
              break;
            }
          }
          saveTo = new File(newFn);
        } else if (retries == 0) {
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
  }

  private static String randomHex(int numOfBytes) {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[numOfBytes];
    random.nextBytes(bytes);
    return Hex.encode(bytes);
  }

  protected static boolean isEnabled(String enabledS, boolean defaultEnabled, String optionName) {
    return (enabledS == null) ? defaultEnabled : isEnabled(enabledS, optionName);
  }

  private static boolean isEnabled(String enabledS, String optionName) {
    if ("yes".equalsIgnoreCase(enabledS) || "enabled".equalsIgnoreCase(enabledS)
        || "true".equalsIgnoreCase(enabledS)) {
      return true;
    } else if ("no".equalsIgnoreCase(enabledS) || "disabled".equalsIgnoreCase(enabledS)
        || "false".equalsIgnoreCase(enabledS)) {
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

  protected char[] readPasswordIfNotSet(String password) throws IOException {
    return readPasswordIfNotSet(null, password);
  }

  protected char[] readPasswordIfNotSet(String prompt, String password) throws IOException {
    return (password != null) ? password.toCharArray() : readPassword(prompt);
  }

  protected char[] readPassword() throws IOException {
    return readPassword(null);
  }

  protected char[] readPassword(String prompt) throws IOException {
    String tmpPrompt = (prompt == null) ? "Password:" : prompt.trim();

    if (!tmpPrompt.endsWith(":")) {
      tmpPrompt += ":";
    }

    String passwordUi = System.getProperty("org.xipki.console.passwordui");
    return "gui".equalsIgnoreCase(passwordUi)
              ? SecurePasswordInputPanel.readPassword(tmpPrompt)
              : readLine(tmpPrompt, '*').toCharArray();
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
    return CollectionUtil.isNonEmpty(col);
  }

  protected static List<String> split(String str, String delim) {
    return StringUtil.split(str, delim);
  }

  protected static BigInteger toBigInt(String str) {
    return toBigInt(str, false);
  }

  protected static BigInteger toBigInt(String str, boolean defaultHex) {
    String tmpStr = str.trim();

    if (tmpStr.startsWith("0x") || tmpStr.startsWith("0X")) {
      if (tmpStr.length() > 2) {
        return new BigInteger(tmpStr.substring(2), 16);
      } else {
        throw new NumberFormatException("invalid integer '" + tmpStr + "'");
      }
    }
    return new BigInteger(tmpStr, defaultHex ? 16 : 10);
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
      tmpPrompt = "[yes/no]? ";
    } else {
      if ('?' == prompt.charAt(prompt.length() - 1)) {
        tmpPrompt = prompt.substring(0, prompt.length() - 1);
      } else {
        tmpPrompt = prompt;
      }
      tmpPrompt += " [yes/no]? ";
    }

    String answer = readLine(tmpPrompt, null);
    if (answer == null) {
      throw new IOException("interrupted");
    }

    int tries = 1;

    while (tries < maxTries) {
      if ("yes".equalsIgnoreCase(answer)) {
        return true;
      } else if ("no".equalsIgnoreCase(answer)) {
        return false;
      } else {
        tries++;
      }
      answer = readLine("Please answer with yes or no: ", null);
    }

    return false;
  }

}
