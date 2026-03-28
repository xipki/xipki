// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.dist;

import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.ca.mgmt.CaMgmtShellMain;
import org.xipki.shell.demo.DemoShellMain;
import org.xipki.shell.pki.client.PkiClientShellMain;
import org.xipki.shell.security.SecurityShellMain;
import org.xipki.shell.xi.XiShellMain;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.io.PrintWriter;
import java.util.Map;

/**
 * Xipki Mgmt Cli Main.
 *
 * @author Lijun Liao (xipki)
 */
public class XipkiMgmtCliMain {

  public static void main(String[] args) throws Exception {
    PicocliShell shell = new PicocliShell("xipki> ", new RootCommand(),
        new PrintWriter(System.out, true));
    CommandLine commandLine = shell.commandLine();
    addModuleSubcommands(commandLine, new XiShellMain.RootCommand());
    addModuleSubcommands(commandLine, new DemoShellMain.RootCommand());
    addModuleSubcommands(commandLine, new SecurityShellMain.RootCommand());
    addModuleSubcommands(commandLine, new PkiClientShellMain.RootCommand());
    addModuleSubcommands(commandLine, new CaMgmtShellMain.RootCommand());
    System.exit(shell.run(args));
  }

  private static void addModuleSubcommands(CommandLine commandLine, Object moduleRoot) {
    CommandLine module = new CommandLine(moduleRoot);
    module.getSubcommands().entrySet().stream()
        .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
        .map(Map.Entry::getValue)
        .forEach(sub -> commandLine.addSubcommand(sub.getCommandName(), sub));
  }

  @Command(name = "xipki-mgmt-cli", description = "XiPKI management CLI",
      mixinStandardHelpOptions = true)
  /**
   * Root command for the combined XiPKI management CLI.
   */
  public static class RootCommand extends ShellBaseCommand {
    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }
  }
}
