// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.demo;

import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.util.extra.misc.ReflectiveUtil;
import picocli.CommandLine.Command;

import java.lang.reflect.Method;
import java.util.function.Consumer;

/**
 * Demo Shell Main.
 *
 * @author Lijun Liao (xipki)
 */
public class DemoShellMain {

  // use reflective method to avoid the dependency of h2.
  private static final String CLASS_SERVER = "org.h2.tools.Server";

  private static Object server;
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
   *
   * @author Lijun Liao (xipki)
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
        server = ReflectiveUtil.newInstance(CLASS_SERVER);
        Method runToolMethod = server.getClass().getMethod("runTool", String[].class);
        runToolMethod.invoke(server, (Object) new String[] {
            "-ifNotExists", "-tcp", "-tcpPort", Integer.toString(tcpPort),
            "-tcpAllowOthers", "-web", "-webPort", Integer.toString(webPort), "-webAllowOthers"});
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

  static void shutdownH2Server(Consumer<String> printer) {
    if (server != null) {
      printer.accept("Shutdown H2 TCP server and Web console server.");
      shutdownServer();
    } else {
      printer.accept("Found no H2 server.");
    }
  }

  private static void shutdownServer() {
    try {
      Method shutdownMethod = server.getClass().getMethod("shutdown");
      shutdownMethod.invoke(server);
      server = null;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

}
