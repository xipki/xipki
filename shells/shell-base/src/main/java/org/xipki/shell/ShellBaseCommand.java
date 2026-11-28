// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.UserInterruptException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.PemEncoder;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

/**
 * Shared base for concrete commands.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ShellBaseCommand implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(ShellBaseCommand.class);

  @Spec
  protected CommandSpec spec;

  protected PrintWriter out() {
    return spec.commandLine().getOut();
  }

  protected void println(String text) {
    out().println(text);
    out().flush();
  }

  protected char[] readPassword(String prompt) throws IOException, PasswordResolverException {
    String effectivePrompt = prompt == null ? "Password" : prompt;
    Console console = System.console();
    char[] password;
    if (console != null) {
      password = console.readPassword("%s: ", effectivePrompt);
    } else {
      out().print(effectivePrompt + ": ");
      out().flush();
      String line = readStdinLine();
      password = line == null ? null : line.toCharArray();
    }

    if (password == null || password.length == 0) {
      return password;
    }
    return Passwords.resolvePassword(new String(password));
  }

  protected char[] readPasswordIfNotSet(String prompt, String passwordHint)
      throws IOException, PasswordResolverException {
    return passwordHint != null ? Passwords.resolvePassword(passwordHint) : readPassword(prompt);
  }

  protected boolean confirmAction(String prompt) throws IOException {
    String answer = readPrompt(prompt + " (yes/no): ");
    return StringUtil.orEqualsIgnoreCase(answer, "yes", "y");
  }

  protected String readPrompt(String prompt) throws IOException {
    String tmpPrompt = prompt;
    if (StringUtil.isNotBlank(prompt) && !prompt.endsWith(" ")) {
      tmpPrompt += " ";
    }

    LineReader reader = PicocliShell.activeLineReader();
    if (reader != null) {
      Object historyDisabledVar = reader.getVariable(LineReader.DISABLE_HISTORY);
      try {
        reader.setVariable(LineReader.DISABLE_HISTORY, Boolean.TRUE);
        return reader.readLine(tmpPrompt);
      } catch (UserInterruptException | EndOfFileException ex) {
        throw new IOException("interrupted", ex);
      } finally {
        if (historyDisabledVar != null) {
          reader.setVariable(LineReader.DISABLE_HISTORY, historyDisabledVar);
        } else {
          reader.getVariables().remove(LineReader.DISABLE_HISTORY);
        }
      }
    }

    out().print(tmpPrompt);
    out().flush();
    return readStdinLine();
  }

  /** The reader of {@link #stdinSource}, shared by all reads of the standard input. */
  private static BufferedReader stdinReader;

  private static InputStream stdinSource;

  /**
   * Reads a line from the standard input. One reader is shared by all reads: a reader per read
   * would buffer the following lines of a piped input and lose them.
   *
   * @return the line, {@code null} at the end of the input.
   * @throws IOException if reading fails.
   */
  protected static String readStdinLine() throws IOException {
    synchronized (ShellBaseCommand.class) {
      if (stdinReader == null || stdinSource != System.in) {
        stdinSource = System.in;
        stdinReader = new BufferedReader(new InputStreamReader(stdinSource));
      }
      return stdinReader.readLine();
    }
  }

  protected void saveVerbose(String promptPrefix, String file, byte[] content)
      throws IOException {
    saveVerbose(promptPrefix, Paths.get(file), content);
  }

  /**
   * Saves the content to the file. If the file exists, the user is asked whether to replace it
   * or to give another path; if saving fails, the user is asked for another path (twice).
   *
   * @throws IOException if the content could not be saved, also if a question could not be
   *         answered (e.g. the end of the input in a script): nothing is saved then.
   */
  protected void saveVerbose(String promptPrefix, Path file, byte[] content) throws IOException {
    File saveTo = new File(IoUtil.expandFilepath(file.toString()));
    saveTo = confirmTarget(saveTo);

    int retries = 2;
    while (true) {
      try {
        save(saveTo, content);
        break;
      } catch (IOException ex) {
        if (retries-- <= 0) {
          LogUtil.error(LOG, ex, "could not save to file");
          throw new IOException("could not save to file " + saveTo.getPath() + ": "
              + ex.getMessage(), ex);
        }
        println("ERROR: " + ex.getMessage());
        saveTo = confirmTarget(promptSaveTarget());
      }
    }

    String tmpPromptPrefix = StringUtil.isBlank(promptPrefix) ? "saved to file" : promptPrefix;
    println(tmpPromptPrefix + " " + saveTo.getPath());
  }

  /**
   * Returns the file to save to: the given one if it does not exist or may be replaced,
   * otherwise another one entered by the user.
   */
  private File confirmTarget(File file) throws IOException {
    File saveTo = file;
    boolean firstQuestion = true;
    while (saveTo.exists()) {
      String answer = readPrompt(firstQuestion
          ? "A file named '" + saveTo.getPath() + "' already exists. Do you want to replace it "
              + "[Yes/No]? "
          : "Please answer with Yes or No: ");
      if (answer == null) {
        throw new IOException("file " + saveTo.getPath()
            + " exists and was not replaced (no answer)");
      }

      if (StringUtil.orEqualsIgnoreCase(answer, "yes", "y")) {
        break;
      } else if (StringUtil.orEqualsIgnoreCase(answer, "no", "n")) {
        firstQuestion = true;
        saveTo = promptSaveTarget();
      } else {
        firstQuestion = false;
      }
    }
    return saveTo;
  }

  private File promptSaveTarget() throws IOException {
    while (true) {
      String newFn = readPrompt("Enter new path to save to ... ");
      if (newFn == null) {
        throw new IOException("no path to save to was entered (no answer)");
      }
      if (StringUtil.isNotBlank(newFn)) {
        return new File(newFn);
      }
    }
  }

  protected void save(File file, byte[] content) throws IOException {
    File tmpFile = new File(IoUtil.expandFilepath(file.getPath()));
    File parent = tmpFile.getParentFile();
    if (parent != null) {
      IoUtil.mkdirs(parent);
    }

    try (InputStream is = new ByteArrayInputStream(content)) {
      Files.copy(is, tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }
  }

  protected BigInteger toBigInt(String text) {
    return toBigInt(text, null);
  }

  protected BigInteger toBigInt(String text, Boolean hex) {
    String value = text.trim();
    if (StringUtil.startsWithIgnoreCase(value, "0x")) {
      return new BigInteger(value.substring(2), 16);
    }
    return Boolean.TRUE.equals(hex) ? new BigInteger(value, 16) : new BigInteger(value);
  }

  protected byte[] encodeCert(byte[] encodedCert, String outform) throws IOException {
    return derPemEncode(encodedCert, outform, "certificate", PemEncoder.PemLabel.CERTIFICATE);
  }

  protected byte[] encodeCrl(byte[] encodedCrl, String outform) throws IOException {
    return derPemEncode(encodedCrl, outform, "CRL", PemEncoder.PemLabel.X509_CRL);
  }

  protected byte[] derPemEncode(
      byte[] encoded, String outform, String contentType, PemEncoder.PemLabel pemLabel)
      throws IOException {
    if ("pem".equalsIgnoreCase(outform)) {
      return PemEncoder.encode(encoded, pemLabel);
    } else if ("der".equalsIgnoreCase(outform)) {
      return encoded;
    } else {
      throw new IOException("unknown " + contentType + " outform " + outform);
    }
  }

  protected byte[] derPemEncode(byte[] encoded, String outform, PemEncoder.PemLabel pemLabel)
      throws IOException {
    return derPemEncode(encoded, outform, "output", pemLabel);
  }


}
