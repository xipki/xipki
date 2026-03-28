// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.OBFPasswordService;
import org.xipki.util.password.PBEPasswordService;
import org.xipki.util.password.Passwords;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Security actions to protect the password.
 *
 * @author Lijun Liao (xipki)
 */
public class PasswordCommands {
  @Command(name = "deobfuscate", description = "deobfuscate password",
      mixinStandardHelpOptions = true)
  static class DeobfuscateCommand extends ShellBaseCommand {

    @Option(names = "--password", description = "obfuscated password")
    private String passwordHint;

    @Option(names = "--password-file", description = "file containing the obfuscated password")
    @Completion(FilePathCompleter.class)
    private String passwordFile;

    @Option(names = "--out", description = "where to save the password")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        if ((passwordHint == null) == (passwordFile == null)) {
          throw new IllegalArgumentException(
              "exactly one of password and password-file must be specified");
        }

        if (passwordHint == null) {
          passwordHint = StringUtil.toUtf8String(IoUtil.read(passwordFile));
        }

        if (!StringUtil.startsWithIgnoreCase(passwordHint, OBFPasswordService.PROTOCOL_OBF + ":")) {
          throw new IllegalArgumentException("encrypted password does not start with OBF:");
        }

        String password = OBFPasswordService.deobfuscate(passwordHint);
        if (outFile != null) {
          saveVerbose("saved the password to file", outFile, StringUtil.toUtf8Bytes(password));
        } else {
          println("the password is: '" + password + "'");
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "obfuscate", description = "obfuscate password", mixinStandardHelpOptions = true)
  static class ObfuscateCommand extends ShellBaseCommand {

    @Option(names = "--out", description = "where to save the obfuscated password")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(names = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Override
    public void run() {
      try {
        Args.range(quorum, "k", 1, 10);

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
          saveVerbose("saved the obfuscated password to file",
              outFile, StringUtil.toUtf8Bytes(passwordHint));
        } else {
          println("the obfuscated password is: '" + passwordHint + "'");
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "pbe-dec", description = "decrypt password with master password",
      mixinStandardHelpOptions = true)
  static class PbeDecCommand extends ShellBaseCommand {

    @Option(names = "--password", description = "encrypted password")
    private String passwordHint;

    @Option(names = "--password-file", description = "file containing the encrypted password")
    @Completion(FilePathCompleter.class)
    private String passwordFile;

    @Option(names = "--out", description = "where to save the password")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        if ((passwordHint == null) == (passwordFile == null)) {
          throw new IllegalArgumentException(
              "exactly one of password and password-file must be specified");
        }

        if (passwordHint == null) {
          passwordHint = StringUtil.toUtf8String(IoUtil.read(passwordFile));
        }

        if (!StringUtil.startsWithIgnoreCase(passwordHint, PBEPasswordService.PROTOCOL_PBE + ":")) {
          throw new IllegalArgumentException("encrypted password does not start with PBE:");
        }

        char[] password = Passwords.resolvePassword(passwordHint);
        if (outFile != null) {
          saveVerbose("saved the password to file", outFile,
              StringUtil.toUtf8Bytes(new String(password)));
        } else {
          println("the password is: '" + new String(password) + "'");
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "pbe-enc", description = "encrypt password with master password",
      mixinStandardHelpOptions = true)
  static class PbeEncCommand extends ShellBaseCommand {

    @Option(names = "--out", description = "where to save the encrypted password")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(names = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Override
    public void run() {
      try {
        Args.range(quorum, "k", 1, 10);

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

        String passwordHint = Passwords.protectPassword(PBEPasswordService.PROTOCOL_PBE, password);
        if (outFile != null) {
          saveVerbose("saved the encrypted password to file",
              outFile, StringUtil.toUtf8Bytes(passwordHint));
        } else {
          println("the encrypted password is: '" + passwordHint + "'");
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }
}
