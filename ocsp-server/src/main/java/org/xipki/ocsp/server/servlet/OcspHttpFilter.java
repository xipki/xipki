// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.server.OcspConf;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.security.Securities;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.http.HttpConstants;
import org.xipki.util.extra.http.XiHttpFilter;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.extra.http.XiHttpResponse;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.XipkiBaseDir;

import java.io.IOException;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspHttpFilter implements XiHttpFilter {

  private static final Logger LOG =
      LoggerFactory.getLogger(OcspHttpFilter.class);

  private static final String DFLT_CFG = "etc/ocsp/ocsp.json";

  private final Securities securities;

  private final OcspServer server;

  private final OcspHealthCheckServlet healthServlet;

  private final HttpOcspServlet ocspServlet;

  public OcspHttpFilter() throws Exception {
    XipkiBaseDir.init();

    OcspConf conf;
    try {
      conf = OcspConf.readConfFromFile(DFLT_CFG);
    } catch (IOException ex) {
      throw new IOException("could not parse configuration file "
          + DFLT_CFG, ex);
    } catch (InvalidConfException ex) {
      throw new InvalidConfException("could not parse configuration file "
          + DFLT_CFG, ex);
    }

    boolean logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    securities = new Securities();
    securities.init(conf.getSecurity());

    OcspServer ocspServer = new OcspServer();
    ocspServer.setSecurityFactory(securities.getSecurityFactory());
    ocspServer.setConfFile(conf.getServerConf());

    try {
      ocspServer.init(true);
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not start OCSP server");
    }

    this.server = ocspServer;
    healthServlet = new OcspHealthCheckServlet(this.server);
    ocspServlet = new HttpOcspServlet(logReqResp, this.server);
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
  public void doFilter(XiHttpRequest req, XiHttpResponse resp)
      throws IOException {
    // In Tomcat, req.getServletPath() will delete one %2F (/) if the URI
    // contains %2F%F (aka // after decoding). This may happen if the OCSP
    // request is sent via GET.
    // String path = req.getServletPath();

    // So we use the following method to retrieve the servletPath.
    String requestUri = req.getRequestURI();
    String contextPath = req.getContextPath();

    String path = (requestUri.length() == contextPath.length()) ? "/"
        : requestUri.substring(contextPath.length());

    if (path.startsWith("/health/")) {
      // 7 = "/health".length()
      String servletPath = path.substring(7);
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, servletPath);
      healthServlet.service(req, resp);
    } else {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path);
      ocspServlet.service(req, resp);
    }
  } // method doFilter
}
