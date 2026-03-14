// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.h2.tools.Server;
import org.xipki.shell.Completers;
import org.xipki.shell.XiAction;

/**
 * Actions of H2 database
 *
 * @author Lijun Liao (xipki)
 */
public class H2DatabaseActions {

  private static Server server;
  private static long startedWebPort;
  private static long startedTcpPort;

  @Command(scope = "demo", name = "start-h2-server", description = "Start H2 server")
  @Service
  public static class StartH2Server extends XiAction {

    @Option(name = "--web-port", description = "H2 server web port")
    @Completion(Completers.DerPemCompleter.class)
    protected String webPort = "8282";

    @Option(name = "--tcp-port", description = "H2 server TCP port")
    @Completion(Completers.DerPemCompleter.class)
    protected String tcpPort = "9092";

    @Override
    protected Object execute0() throws Exception {
      if (server != null) {
        println("H2 TCP server and Web console server " +
            "have been started before with tcpPort=" + startedTcpPort +
            " and webPort=" + startedWebPort);
      } else {
        server = new Server();
        server.runTool("-ifNotExists",
            "-tcp", "-tcpPort", tcpPort, "-tcpAllowOthers",
            "-web", "-webPort", webPort, "-webAllowOthers");
        startedWebPort = Integer.parseInt(webPort);
        startedTcpPort = Integer.parseInt(tcpPort);
        println("Started H2 TCP server and Web console server.");
        Runtime.getRuntime().addShutdownHook(
            new Thread(() -> {
              if (server != null) {
                println("Shutdown H2 TCP server and Web console server.");
                server.shutdown();
                server = null;
              }
            }));
      }

      println("Please point your browser to http://localhost:" +
          startedWebPort + " for H2 database console.");

      return null;
    }

  }

  @Command(scope = "demo", name = "shutdown-h2-server", description = "Shutdown H2 server")
  @Service
  public static class ShutdownH2Server extends XiAction {

    @Override
    protected Object execute0() throws Exception {
      if (server != null) {
        println("Shutdown H2 TCP server and Web console server.");
        server.shutdown();
        server = null;
      } else {
        println("Found no H2 server.");
      }
      return null;
    }

  }

}
