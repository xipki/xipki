// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.xi;

import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import picocli.CommandLine.Command;

/**
 * Xi Shell Main.
 *
 * @author Lijun Liao (xipki)
 */
public class XiShellMain {

  public static void main(String[] args) throws Exception {
    System.exit(PicocliShell.run("xipki> ", new RootCommand(), args));
  }

  @Command(name = "xi", description = "Xi utility commands", subcommands = {
      XiCommands.Uppercase.class,
      XiCommands.Lowercase.class,
      XiCommands.Confirm.class,
      XiCommands.CopyDir.class,
      XiCommands.CopyFile.class,
      XiCommands.FileExists.class,
      XiCommands.Base64EnDecode.class,
      XiCommands.CurlCommand.class,
      XiCommands.Mkdir.class,
      XiCommands.MoveDir.class,
      XiCommands.MoveFile.class,
      XiCommands.Replace.class,
      XiCommands.Rm.class,
      XiCommands.DateTime.class,
      XiCommands.OsInfo.class,
      XiCommands.ExecTerminalCommand.class
  }, mixinStandardHelpOptions = true)
  /**
   * Root command for the Xi utility shell.
   *
   * @author Lijun Liao (xipki)
   */
  public static class RootCommand extends ShellBaseCommand {

    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }
  }

}
