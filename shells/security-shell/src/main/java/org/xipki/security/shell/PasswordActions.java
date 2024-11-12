// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.password.OBFPasswordService;
import org.xipki.password.PBEPasswordService;
import org.xipki.password.Passwords;
import org.xipki.security.shell.SecurityActions.SecurityAction;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

/**
 * Security actions to protect the password.
 *
 * @author Lijun Liao (xipki)
 */

public class PasswordActions {

  @Command(scope = "xi", name = "deobfuscate", description = "deobfuscate password")
  @Service
  public static class Deobfuscate extends SecurityAction {

    @Option(name = "--password", description = "obfuscated password, starts with "
            + OBFPasswordService.PROTOCOL_OBF + ":\n"
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
      if ((passwordHint == null) == (passwordFile == null)) {
        throw new IllegalCmdParamException("exactly one of password and password-file must be specified");
      }

      if (passwordHint == null) {
        passwordHint = StringUtil.toUtf8String(IoUtil.read(passwordFile));
      }

      if (!StringUtil.startsWithIgnoreCase(passwordHint, OBFPasswordService.PROTOCOL_OBF + ":")) {
        throw new IllegalCmdParamException("encrypted password '" + passwordHint + "' does not start with OBF:");
      }

      String password = OBFPasswordService.deobfuscate(passwordHint);
      if (outFile != null) {
        saveVerbose("saved the password to file", outFile, StringUtil.toUtf8Bytes(password));
      } else {
        println("the password is: '" + password + "'");
      }
      return null;
    }

  } // class Deobfuscate

  @Command(scope = "xi", name = "obfuscate", description = "obfuscate password")
  @Service
  public static class Obfuscate extends SecurityAction {

    @Option(name = "--out", description = "where to save the encrypted password")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Override
    protected Object execute0() throws Exception {
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
        saveVerbose("saved the obfuscated password to file", outFile, StringUtil.toUtf8Bytes(passwordHint));
      } else {
        println("the obfuscated password is: '" + passwordHint + "'");
      }
      return null;
    }

  } // class Obfuscate

  @Command(scope = "xi", name = "pbe-dec", description = "decrypt password with master password")
  @Service
  public static class PbeDec extends SecurityAction {

    @Option(name = "--password", description = "encrypted password, starts with PBE:\n"
            + "exactly one of password and password-file must be specified")
    private String passwordHint;

    @Option(name = "--password-file", description = "file containing the encrypted password")
    @Completion(FileCompleter.class)
    private String passwordFile;

    @Option(name = "--out", description = "where to save the password")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      if ((passwordHint == null) == (passwordFile == null)) {
        throw new IllegalCmdParamException("exactly one of password and password-file must be specified");
      }

      if (passwordHint == null) {
        passwordHint = StringUtil.toUtf8String(IoUtil.read(passwordFile));
      }

      if (!StringUtil.startsWithIgnoreCase(passwordHint, PBEPasswordService.PROTOCOL_PBE + ":")) {
        throw new IllegalCmdParamException("encrypted password '" + passwordHint + "' does not start with PBE:");
      }

      char[] password = Passwords.resolvePassword(passwordHint);

      if (outFile != null) {
        saveVerbose("saved the password to file", outFile, StringUtil.toUtf8Bytes(new String(password)));
      } else {
        println("the password is: '" + new String(password) + "'");
      }
      return null;
    } // method execute0

  } // class PbeDec

  @Command(scope = "xi", name = "pbe-enc", description = "encrypt password with master password")
  @Service
  public static class PbeEnc extends SecurityAction {

    @Option(name = "--out", description = "where to save the encrypted password")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Override
    protected Object execute0() throws Exception {
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
        saveVerbose("saved the encrypted password to file", outFile, StringUtil.toUtf8Bytes(passwordHint));
      } else {
        println("the encrypted password is: '" + passwordHint + "'");
      }
      return null;
    } // method execute0

  } // class PbeEnc

}
