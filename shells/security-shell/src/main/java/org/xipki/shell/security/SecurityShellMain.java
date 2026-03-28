// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.security.util.KeyUtil;
import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import picocli.CommandLine.Command;

/**
 * Security Shell Main.
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityShellMain {

  public static void main(String[] args) throws Exception {
    System.exit(PicocliShell.run("xipki> ", new RootCommand(), args));
  }

  @Command(name = "security", description = "Security commands", subcommands = {
      PasswordCommands.DeobfuscateCommand.class,
      PasswordCommands.ObfuscateCommand.class,
      PasswordCommands.PbeDecCommand.class,
      PasswordCommands.PbeEncCommand.class,
      SecurityCommands.CertInfoCommand.class,
      CsrCommands.CrlInfoCommand.class,
      SecurityCommands.ConvertKeystoreCommand.class,
      SecurityCommands.ImportCertCommand.class,
      SecurityCommands.ExportCertP7mCommand.class,
      SecurityCommands.ExportKeyCertPemCommand.class,
      SecurityCommands.ExportKeyCertEstCommand.class,
      P12Commands.SecretkeyP12Command.class,
      P12Commands.ExportCertP12Command.class,
      P12Commands.UpdateCertP12Command.class,
      P12Commands.KeypairP12Command.class,
      P12Commands.Pkcs12Command.class,
      CsrCommands.CsrJceCommand.class,
      CsrCommands.CsrP11Command.class,
      CsrCommands.CsrP12Command.class,
      P11Commands.KeypairP11Command.class,
      P11Commands.DeleteKeyP11Command.class,
      P11Commands.ObjectExistsP11Command.class,
      P11Commands.DeleteObjectsP11Command.class,
      P11Commands.DeleteAllObjectsP11Command.class,
      P11Commands.SecretkeyP11Command.class,
      P11Commands.ImportSecretkeyP11Command.class,
      P11Commands.TokenInfoP11Command.class,
      QaSecurityCommands.SpeedKeypairGenP11Command.class,
      QaSecurityCommands.SpeedSignP11Command.class,
      QaSecurityCommands.SpeedKeypairGenP12Command.class,
      QaSecurityCommands.SpeedSignP12Command.class,
      CsrCommands.ValidateCsrCommand.class
  }, mixinStandardHelpOptions = true)
  /**
   * Root command for the security shell.
   */
  public static class RootCommand extends ShellBaseCommand {

    public RootCommand() {
      KeyUtil.addProviders();
    }

    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }
  }
}
