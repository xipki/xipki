// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.util.Args;
import org.xipki.ocsp.server.OcspConf;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.ResponderAndPath;
import org.xipki.pkix.Securities;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.pkix.util.io.XipkiBaseDir;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * OCSP Http Filter.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(OcspHttpFilter.class);

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
    } catch (InvalidConfException ex) {
      throw new InvalidConfException("could not parse configuration file " + DFLT_CFG, ex);
    }

    boolean logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    securities = new Securities();
    securities.init(conf.security());

    OcspServer ocspServer = new OcspServer();
    ocspServer.setSecurityFactory(securities.securityFactory());
    ocspServer.setConfFile(conf.serverConf());

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
  public void doFilter(XiHttpRequest req, XiHttpResponse resp) throws IOException {
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

  /**
   * HTTP health check servlet of the OCSP server.
   *
   * @author Lijun Liao (xipki)
   */
  private static class OcspHealthCheckServlet {

    private static final Logger LOG = LoggerFactory.getLogger(OcspHealthCheckServlet.class);

    private final OcspServer server;

    public OcspHealthCheckServlet(OcspServer server) {
      this.server = Args.notNull(server, "server");
    }

    public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
      String method = req.getMethod();
      if (!("GET".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method))) {
        resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
      }
      service0(req).fillResponse(resp);
    }

    private HttpResponse service0(XiHttpRequest req) {

      Map<String, String> headers = new HashMap<>();
      headers.put("Access-Control-Allow-Origin", "*");

      try {
        String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
        ResponderAndPath responderAndPath = server.getResponderForPath(path);
        if (responderAndPath == null) {
          return new HttpResponse(HttpStatusCode.SC_NOT_FOUND, null, headers, null);
        }

        boolean healthy = server.healthCheck(responderAndPath.responder());
        int status = healthy ? HttpStatusCode.SC_OK : HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
        return new HttpResponse(status, null, headers, null);
      } catch (Throwable th) {
        LOG.error("Throwable thrown, this should not happen", th);
        return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR, null, headers, null);
      }
    }

  }

}
