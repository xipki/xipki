// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.license.api.LicenseFactory;
import org.xipki.ocsp.server.OcspServerImpl;
import org.xipki.ocsp.servlet.OcspConf.RemoteMgmt;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.HttpConstants;
import org.xipki.util.LogUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(OcspServletFilter.class);

  private static final String DFLT_CONF_FILE = "etc/ocsp/ocsp.json";

  private Securities securities;

  private LicenseFactory licenseFactory;

  private OcspServerImpl server;

  private HealthCheckServlet healthServlet;

  private OcspServlet ocspServlet;

  private boolean remoteMgmtEnabled;

  private HttpMgmtServlet mgmtServlet;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    XipkiBaseDir.init();

    String confFile = DFLT_CONF_FILE;

    OcspConf conf;
    try {
      conf = OcspConf.readConfFromFile(confFile);
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse OCSP configuration file " + confFile, ex);
    }

    boolean logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    securities = new Securities();
    try {
      securities.init(conf.getSecurity());
    } catch (IOException | InvalidConfException ex) {
      LogUtil.error(LOG, ex, "could not initialize Securities");
      return;
    }

    String str = filterConfig.getInitParameter("licenseFactory");
    LOG.info("Use licenseFactory: {}", str);
    try {
      licenseFactory = (LicenseFactory) Class.forName(str).getDeclaredConstructor().newInstance();
    } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException |
             InvocationTargetException ex) {
      throw new ServletException("could not initialize LicenseFactory", ex);
    }

    OcspServerImpl ocspServer = new OcspServerImpl(licenseFactory.createOcspLicense());
    ocspServer.setSecurityFactory(securities.getSecurityFactory());
    ocspServer.setConfFile(conf.getServerConf());

    try {
      ocspServer.init();
    } catch (InvalidConfException | PasswordResolverException ex) {
      LogUtil.error(LOG, ex, "could not start OCSP server");
    }

    this.server = ocspServer;
    this.healthServlet = new HealthCheckServlet();
    this.healthServlet.setServer(this.server);

    this.ocspServlet = new OcspServlet();
    this.ocspServlet.setServer(this.server);
    this.ocspServlet.setLogReqResp(logReqResp);

    RemoteMgmt remoteMgmt = conf.getRemoteMgmt();
    this.remoteMgmtEnabled = remoteMgmt != null && remoteMgmt.isEnabled();
    LOG.info("remote management is {}", remoteMgmtEnabled ? "enabled" : "disabled");

    if (remoteMgmtEnabled) {
      if (CollectionUtil.isNotEmpty(remoteMgmt.getCerts())) {
        List<X509Cert> certs = null;
        try {
          certs = X509Util.parseCerts(remoteMgmt.getCerts());
        } catch (InvalidConfException ex) {
          LogUtil.error(LOG, ex, "could not parse client certificates, disable the remote management");
        }

        if (CollectionUtil.isEmpty(certs)) {
          LOG.error("could not find any valid client certificates, disable the remote management");
        } else {
          mgmtServlet = new HttpMgmtServlet();
          mgmtServlet.setMgmtCerts(CollectionUtil.listToSet(certs));
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

    if (licenseFactory != null) {
      licenseFactory.close();
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
