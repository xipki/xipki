/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.scep4j.serveremulator;

import java.util.Arrays;
import java.util.List;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 * @author Lijun Liao
 */

public class ScepServerContainer
{
    private Server server;

    public ScepServerContainer(
            final int port,
            final ScepServer scepServer)
    throws Exception
    {
        this(port, Arrays.asList(scepServer));
    }

    public ScepServerContainer(
            final int port,
            final List<ScepServer> scepServers)
    throws Exception
    {
        Server server = new Server(port);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);

        for(ScepServer m : scepServers)
        {
            String servletPattern = "/" + m.getName() + "/pkiclient.exe/*";
            ScepServlet servlet = m.getServlet();
            context.addServlet(new ServletHolder(servlet), servletPattern);
        }

        this.server = server;
    }

    public void start()
    throws Exception
    {
        try
        {
            server.start();
        }catch(Exception e)
        {
            server.stop();
            throw e;
        }
    }

    public void stop()
    throws Exception
    {
        server.stop();
    }
}
