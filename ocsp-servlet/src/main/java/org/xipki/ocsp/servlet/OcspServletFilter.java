/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

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
import org.xipki.ocsp.server.OcspServerImpl;
import org.xipki.ocsp.servlet.OcspConf.RemoteMgmt;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.FileOrBinary;
import org.xipki.util.HttpConstants;
import org.xipki.util.InvalidConfException;
import org.xipki.util.LogUtil;
import org.xipki.util.XipkiBaseDir;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao
 */

public class OcspServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(OcspServletFilter.class);

  private static final String DFLT_CONF_FILE = "etc/ocsp/ocsp.json";

  private Securities securities;

  private OcspServerImpl server;

  private HealthCheckServlet healthServlet;

  private OcspServlet ocspServlet;

  private boolean remoteMgmtEnabled;

  private boolean logReqResp;

  private HttpMgmtServlet mgmtServlet;

  @Override
  public void init(FilterConfig filterConfig)
      throws ServletException {
    XipkiBaseDir.init();

    String confFile = DFLT_CONF_FILE;

    OcspConf conf;
    try {
      conf = OcspConf.readConfFromFile(confFile);
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse OCSP configuration file " + confFile, ex);
    }

    String str = filterConfig.getInitParameter("logReqResp");
    logReqResp = Boolean.parseBoolean(str);
    LOG.info("logReqResp: {}", logReqResp);

    securities = new Securities();
    try {
      securities.init(conf.getSecurity());
    } catch (IOException | InvalidConfException ex) {
      LogUtil.error(LOG, ex, "could not initialize Securities");
      return;
    }

    OcspServerImpl ocspServer = new OcspServerImpl();
    ocspServer.setSecurityFactory(securities.getSecurityFactory());
    ocspServer.setConfFile(conf.getServerConf());

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
    this.ocspServlet.setLogReqResp(logReqResp);

    RemoteMgmt remoteMgmt = conf.getRemoteMgmt();
    this.remoteMgmtEnabled = remoteMgmt == null ? false : remoteMgmt.isEnabled();
    LOG.info("remote management is {}", remoteMgmtEnabled ? "enabled" : "disabled");

    if (remoteMgmtEnabled) {
      if (CollectionUtil.isNotEmpty(remoteMgmt.getCerts())) {
        Set<X509Cert> certs = new HashSet<>();

        for (FileOrBinary m : remoteMgmt.getCerts()) {
          try {
            X509Cert cert = X509Util.parseCert(m.readContent());
            certs.add(cert);
          } catch (CertificateException | IOException ex) {
            String msg = "could not parse the client certificate";
            if (m.getFile() != null) {
              msg += " " + m.getFile();
            }
            LogUtil.error(LOG, ex, msg);
          }
        }

        if (certs.isEmpty()) {
          LOG.error("could not find any valid client certificates, disable the remote management");
        } else {
          mgmtServlet = new HttpMgmtServlet();
          mgmtServlet.setMgmtCerts(certs);
          mgmtServlet.setOcspServer(server);
        }
      }
    }
  } // method init

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

    // In Tomcat, req.getServletPath() will delete one %2F (/) if the URI contains
    // %2F%F (aka // after decoding). This may happen if the OCSP request is sent via GET.
    // String path = req.getServletPath();

    // So we use the following method to retrieve the servletPath.
    String requestUri = req.getRequestURI();
    String contextPath = req.getContextPath();

    String path;
    if (requestUri.length() == contextPath.length()) {
      path = "/";
    } else {
      path = requestUri.substring(contextPath.length());
    }

    if (path.startsWith("/health/")) {
      String servletPath = path.substring(7); // 7 = "/health".length()
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, servletPath);
      healthServlet.service(req, resp);
    } else if (path.startsWith("/mgmt/")) {
      if (remoteMgmtEnabled) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/mgmt".length()
        mgmtServlet.service(req, resp);
      } else {
        resp.sendError(HttpServletResponse.SC_FORBIDDEN);
      }
    } else {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path);
      ocspServlet.service(req, resp);
    }
  } // method doFilter

}
