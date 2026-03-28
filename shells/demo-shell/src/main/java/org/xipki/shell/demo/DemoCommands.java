// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.demo;

import org.xipki.shell.ShellBaseCommand;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Demo shell commands.
 *
 * @author Lijun Liao (xipki)
 */
class DemoCommands {

  @Command(name = "start-h2-server", description = "Start H2 server",
      mixinStandardHelpOptions = true)
  static class StartH2ServerCommand extends ShellBaseCommand {

    @Option(names = "--web-port", description = "H2 server web port")
    private int webPort = 8282;

    @Option(names = "--tcp-port", description = "H2 server TCP port")
    private int tcpPort = 9092;

    @Override
    public void run() {
      DemoShellMain.startH2Server(this::println, webPort, tcpPort);
    }
  }

  @Command(name = "shutdown-h2-server", description = "Shutdown H2 server",
      mixinStandardHelpOptions = true)
  static class ShutdownH2ServerCommand extends ShellBaseCommand {

    @Override
    public void run() {
      DemoShellMain.shutdownH2Server(this::println);
    }
  }

}
