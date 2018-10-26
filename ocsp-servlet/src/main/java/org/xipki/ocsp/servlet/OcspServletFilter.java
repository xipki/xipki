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

package org.xipki.ocsp.servlet;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.xipki.datasource.DataAccessException;
import org.xipki.ocsp.api.internal.OcspStoreFactoryRegisterImpl;
import org.xipki.ocsp.server.impl.OcspServerImpl;
import org.xipki.ocsp.store.OcspStoreFactoryImpl;
import org.xipki.password.PasswordResolverException;
import org.xipki.securities.Securities;
import org.xipki.util.InvalidConfException;

/**
 * TODO.
 * @author Lijun Liao
 */

public class OcspServletFilter implements Filter {

  static final String ATTR_XIPKI_PATH = "xipki_path";

  private static final String DFLT_OCSP_SERVER_CFG = "xipki/etc/ocsp/ocsp-responderxml";

  private Securities securities;

  private OcspServerImpl server;

  private HealthCheckServlet healthServlet;

  private OcspServlet ocspServlet;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    securities = new Securities();
    try {
      securities.init();
    } catch (IOException | InvalidConfException ex) {
      throw new ServletException("Exception while initializing Securites", ex);
    }

    OcspServerImpl ocspServer = new OcspServerImpl();
    ocspServer.setSecurityFactory(securities.getSecurityFactory());

    OcspStoreFactoryRegisterImpl ocspStoreFactoryRegister = new OcspStoreFactoryRegisterImpl();
    ocspStoreFactoryRegister.registFactory(new OcspStoreFactoryImpl());

    ocspServer.setOcspStoreFactoryRegister(ocspStoreFactoryRegister);

    ocspServer.setConfFile(DFLT_OCSP_SERVER_CFG);

    try {
      ocspServer.init();
    } catch (InvalidConfException | DataAccessException | PasswordResolverException ex) {
      throw new ServletException("Exception while initializing OCSP server", ex);
    }

    this.server = ocspServer;
    this.healthServlet = new HealthCheckServlet();
    this.healthServlet.setServer(this.server);

    this.ocspServlet = new OcspServlet();
    this.ocspServlet.setServer(this.server);
  }

  @Override
  public void destroy() {
    if (securities != null) {
      securities.close();
    }

    if (server != null) {
      server.close();
    }
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;
    String path = req.getServletPath();

    if (path.startsWith("/health/")) {
      String servletPath = path.substring(7); // 7 = "/health".length()
      req.setAttribute(ATTR_XIPKI_PATH, servletPath);
      healthServlet.service(req, resp);
    } else {
      req.setAttribute(ATTR_XIPKI_PATH, path);
      ocspServlet.service(req, resp);
    }
  }

}
