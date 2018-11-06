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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.ocsp.api.internal.OcspStoreFactoryRegisterImpl;
import org.xipki.ocsp.server.impl.OcspServerImpl;
import org.xipki.ocsp.store.OcspStoreFactoryImpl;
import org.xipki.password.PasswordResolverException;
import org.xipki.securities.Securities;
import org.xipki.util.HttpConstants;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class OcspServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(OcspServletFilter.class);

  private static final String DFLT_OCSP_SERVER_CFG = "xipki/etc/org.xipki.ocsp.server.cfg";

  private static final String DFLT_CONF_FILE = "xipki/etc/ocsp/ocsp-responder.xml";

  private Securities securities;

  private OcspServerImpl server;

  private HealthCheckServlet healthServlet;

  private OcspServlet ocspServlet;

  private boolean remoteMgmtEnabled;

  private HttpMgmtServlet mgmgServlet;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    securities = new Securities();
    try {
      securities.init();
    } catch (IOException | InvalidConfException ex) {
      LogUtil.error(LOG, ex, "could not initializing Securities");
      return;
    }

    Properties props = new Properties();
    InputStream is = null;
    try {
      is = Files.newInputStream(Paths.get(DFLT_OCSP_SERVER_CFG));
      props.load(is);
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "could not load properties from file " + DFLT_OCSP_SERVER_CFG);
      return;
    } finally {
      IoUtil.closeQuietly(is);
    }

    OcspServerImpl ocspServer = new OcspServerImpl();
    ocspServer.setSecurityFactory(securities.getSecurityFactory());

    OcspStoreFactoryRegisterImpl ocspStoreFactoryRegister = new OcspStoreFactoryRegisterImpl();
    ocspStoreFactoryRegister.registFactory(new OcspStoreFactoryImpl());

    ocspServer.setOcspStoreFactoryRegister(ocspStoreFactoryRegister);

    String confFile = props.getProperty("confFile", DFLT_CONF_FILE);
    ocspServer.setConfFile(confFile);

    try {
      ocspServer.init();
    } catch (InvalidConfException | DataAccessException | PasswordResolverException ex) {
      LogUtil.error(LOG, ex, "could not start OCSP server");
    }

    this.server = ocspServer;
    this.healthServlet = new HealthCheckServlet();
    this.healthServlet.setServer(this.server);

    this.ocspServlet = new OcspServlet();
    this.ocspServlet.setServer(this.server);

    this.remoteMgmtEnabled =
        Boolean.parseBoolean(props.getProperty("remote.mgmt.enabled", "false"));
    LOG.info("remote management is {}", remoteMgmtEnabled ? "enabled" : "disabled");

    if (remoteMgmtEnabled) {
      this.mgmgServlet = new HttpMgmtServlet();
      this.mgmgServlet.setOcspServer(this.server);
    }
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
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, servletPath);
      healthServlet.service(req, resp);
    } else if (path.startsWith("/mgmt/")) {
      if (remoteMgmtEnabled) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/mgmt".length()
        mgmgServlet.service(req, resp);
      } else {
        resp.sendError(HttpServletResponse.SC_FORBIDDEN);
      }
    } else {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path);
      ocspServlet.service(req, resp);
    }
  }

}
