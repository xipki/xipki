// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.demo;

import org.h2.tools.Server;
import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.function.Consumer;

/**
 * Demo Shell Main.
 *
 * @author Lijun Liao (xipki)
 */
public class DemoShellMain {

  private static Server server;
  private static long startedWebPort;
  private static long startedTcpPort;

  public static void main(String[] args) throws Exception {
    System.exit(PicocliShell.run("xipki> ", new RootCommand(), args));
  }

  @Command(name = "demo", description = "Demo commands", subcommands = {
      DemoCommands.StartH2ServerCommand.class,
      DemoCommands.ShutdownH2ServerCommand.class
  }, mixinStandardHelpOptions = true)
  /**
   * Root command for the demo shell.
   */
  public static class RootCommand extends ShellBaseCommand {

    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }
  }

  static void startH2Server(Consumer<String> printer, int webPort, int tcpPort) {
    try {
      if (server != null) {
        printer.accept("H2 TCP server and Web console server have been started before with tcpPort="
            + startedTcpPort + " and webPort=" + startedWebPort);
      } else {
        // assign the field only after the server has been started successfully, otherwise
        // a second call would wrongly assume that the server is running.
        Server newServer = new Server();
        try {
          newServer.runTool("-ifNotExists", "-tcp", "-tcpPort", Integer.toString(tcpPort),
              "-tcpAllowOthers", "-web", "-webPort", Integer.toString(webPort),
              "-webAllowOthers");
        } catch (Exception ex) {
          newServer.shutdown();
          if (isH2TcpServerRunning(tcpPort)) {
            printer.accept("Could not start H2 server: " + ex.getMessage());
            printer.accept("Use the H2 TCP server already running on port " + tcpPort
                + " (e.g. started by another xipki shell).");
            return;
          }

          throw new RuntimeException("Could not start H2 server (tcpPort=" + tcpPort
              + ", webPort=" + webPort + "): " + ex.getMessage()
              + ". Is another xipki shell or H2 server still running?", ex);
        }
        server = newServer;
        startedWebPort = webPort;
        startedTcpPort = tcpPort;
        printer.accept("Started H2 TCP server and Web console server.");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          if (server != null) {
            shutdownServer();
          }
        }));
      }

      printer.accept("Please point your browser to http://localhost:" + startedWebPort
          + " for H2 database console.");
    } catch (Exception ex) {
      throw new RuntimeException(ex.getMessage(), ex);
    }
  }

  private static boolean isH2TcpServerRunning(int tcpPort) {
    String url = "jdbc:h2:tcp://localhost:" + tcpPort + "/mem:xipki_h2_probe";
    try (Connection conn = DriverManager.getConnection(url, "sa", "")) {
      return conn.isValid(5);
    } catch (Exception ex) {
      return false;
    }
  }

  static void shutdownH2Server(Consumer<String> printer) {
    if (server != null) {
      printer.accept("Shutdown H2 TCP server and Web console server.");
      shutdownServer();
    } else {
      printer.accept("Found no H2 server.");
    }
  }

  private static void shutdownServer() {
    server.shutdown();
    server = null;
  }

  /**
   * Demo shell commands.
   *
   * @author Lijun Liao (xipki)
   */
  static class DemoCommands {

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

}
