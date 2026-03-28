// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.pki.client;

import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import picocli.CommandLine.Command;

/**
 * Pki Client Shell Main.
 *
 * @author Lijun Liao (xipki)
 */
public class PkiClientShellMain {

  public static void main(String[] args) throws Exception {
    System.exit(PicocliShell.run("xipki> ", new RootCommand(), args));
  }

  @Command(name = "pkic",
      description = "PKI client commands", subcommands = {
      CmpCommands.CmpCaCertCommand.class,
      CmpCommands.CmpCaCertsCommand.class,
      CmpCommands.CmpGetCrlCommand.class,
      CmpCommands.CmpRevokeCommand.class,
      CmpCommands.CmpUnsuspendCommand.class,
      CmpCommands.CmpCsrEnrollCommand.class,
      CmpCommands.CmpEnrollServerkeygenCommand.class,
      CmpCommands.CmpEnrollP11Command.class,
      CmpCommands.CmpEnrollP12Command.class,
      CmpCommands.CmpUpdateServerkeygenCommand.class,
      CmpCommands.CmpUpdateP11Command.class,
      CmpCommands.CmpUpdateP12Command.class,
      OcspCommands.OcspStatusCommand.class,
      ScepCommands.ScepCertpollCommand.class,
      ScepCommands.ScepEnrollCommand.class,
      ScepCommands.ScepCacertCommand.class,
      ScepCommands.ScepGetCertCommand.class,
      ScepCommands.ScepGetCrlCommand.class
  }, mixinStandardHelpOptions = true)
  /**
   * Root command for the PKI client shell.
   */
  public static class RootCommand extends ShellBaseCommand {

    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }

  }
}
