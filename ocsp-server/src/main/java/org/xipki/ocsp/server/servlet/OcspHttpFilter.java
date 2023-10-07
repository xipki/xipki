// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.license.api.LicenseFactory;
import org.xipki.ocsp.server.OcspConf;
import org.xipki.ocsp.server.OcspConf.RemoteMgmt;
import org.xipki.ocsp.server.OcspServerImpl;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.HttpConstants;
import org.xipki.util.LogUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ServletException0;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(OcspHttpFilter.class);

  private static final String DFLT_CONF_FILE = "etc/ocsp/ocsp.json";

  private final Securities securities;

  private final LicenseFactory licenseFactory;

  private final OcspServerImpl server;

  private final HealthCheckServlet healthServlet;

  private final HttpOcspServlet ocspServlet;

  private final boolean remoteMgmtEnabled;

  private HttpMgmtServlet mgmtServlet;

  public OcspHttpFilter(String licenseFactoryClazz) throws ServletException0 {
    XipkiBaseDir.init();

    String confFile = DFLT_CONF_FILE;

    OcspConf conf;
    try {
      conf = OcspConf.readConfFromFile(confFile);
    } catch (IOException | InvalidConfException ex) {
      throw new ServletException0("could not parse OCSP configuration file " + confFile, ex);
    }

    boolean logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    securities = new Securities();
    try {
      securities.init(conf.getSecurity());
    } catch (IOException | InvalidConfException ex) {
      throw new ServletException0("could not initialize Securities", ex);
    }

    LOG.info("Use licenseFactory: {}", licenseFactoryClazz);
    try {
      licenseFactory = (LicenseFactory) Class.forName(licenseFactoryClazz).getDeclaredConstructor().newInstance();
    } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException |
             InvocationTargetException ex) {
      throw new ServletException0("could not initialize LicenseFactory", ex);
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
    healthServlet = new HealthCheckServlet();
    healthServlet.setServer(this.server);

    ocspServlet = new HttpOcspServlet();
    ocspServlet.setServer(this.server);
    ocspServlet.setLogReqResp(logReqResp);

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
  public void doFilter(XiHttpRequest req, XiHttpResponse resp) throws IOException {
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
      if (mgmtServlet != null) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/mgmt".length()
        mgmtServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_FORBIDDEN);
      }
    } else {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path);
      ocspServlet.service(req, resp);
    }
  } // method doFilter
}
