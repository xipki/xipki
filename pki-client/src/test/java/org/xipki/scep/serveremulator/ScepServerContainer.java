// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.xipki.util.codec.Args;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;

/**
 * This class starts and shutdowns the Jetty HTTP server.
 *
 * @author Lijun Liao (xipki)
 */

public class ScepServerContainer {

  private final HttpServer server;

  static class MyHandler implements HttpHandler {

    private final ScepServlet servlet;

    private MyHandler(ScepServlet servlet) {
      this.servlet = servlet;
    }

    @Override
    public void handle(HttpExchange t) throws IOException {
      this.servlet.service(t);
      t.getResponseBody().close();
    }
  }

  public ScepServerContainer(int port, ScepServer scepServer) throws Exception {
    this(port, Collections.singletonList(Args.notNull(scepServer,
        "scepServer")));
  }

  public ScepServerContainer(int port, List<ScepServer> scepServers)
      throws Exception {
    Args.notEmpty(scepServers, "scepServers");
    server = HttpServer.create(new InetSocketAddress(port), 0);

    for (ScepServer m : scepServers) {
      server.createContext("/" + m.getName() + "/pkiclient.exe",
          new MyHandler(m.getServlet()));
    }

    server.setExecutor(null); // creates a default executor
  }

  public void start() throws Exception {
    try {
      server.start();
    } catch (Exception ex) {
      server.stop(5);
      throw ex;
    }
  }

  public void stop() throws Exception {
    server.stop(1);
  }

}
