/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.serveremulator;

import java.util.Arrays;
import java.util.List;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ScepServerContainer {

  private Server server;

  public ScepServerContainer(int port, ScepServer scepServer) throws Exception {
      this(port, Arrays.asList(ScepUtil.requireNonNull("scepServer", scepServer)));
  }

  public ScepServerContainer(int port, List<ScepServer> scepServers) throws Exception {
    ScepUtil.requireNonEmpty("scepServers", scepServers);
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
