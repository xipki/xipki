// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.xipki.util.Args;

import java.util.Collections;
import java.util.List;

/**
 * This class starts and shutdowns the Jetty HTTP server.
 *
 * @author Lijun Liao
 */

public class ScepServerContainer {

  private final Server server;

  public ScepServerContainer(int port, ScepServer scepServer) throws Exception {
    this(port, Collections.singletonList(Args.notNull(scepServer, "scepServer")));
  }

  public ScepServerContainer(int port, List<ScepServer> scepServers) throws Exception {
    Args.notEmpty(scepServers, "scepServers");
    server = new Server(port);
    ServletHandler handler = new ServletHandler();
    server.setHandler(handler);

    for (ScepServer m : scepServers) {
      ServletHolder servletHolder = new ServletHolder(m.getName(), m.getServlet());
      handler.addServletWithMapping(servletHolder, "/" + m.getName() + "/pkiclient.exe");
    }

    server.join();
  }

  public void start() throws Exception {
    try {
      server.start();
    } catch (Exception ex) {
      server.stop();
      throw ex;
    }
  }

  public void stop() throws Exception {
    server.stop();
  }

}
