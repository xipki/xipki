// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet5;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ocsp.server.servlet.OcspServletFilter0;
import org.xipki.util.HttpConstants;
import org.xipki.util.exception.ServletException0;

import java.io.IOException;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspServletFilter implements Filter {

  private OcspServletFilter0 filter0;

  private HealthCheckServlet healthServlet;

  private HttpOcspServlet ocspServlet;

  private HttpMgmtServlet mgmtServlet;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    String licenseFactoryClazz = filterConfig.getInitParameter("licenseFactory");
    try {
      filter0 = new OcspServletFilter0(licenseFactoryClazz);
    } catch (ServletException0 ex) {
      throw new ServletException(ex);
    }

    if (filter0.getHealthServlet() != null) {
      this.healthServlet = new HealthCheckServlet();
      this.healthServlet.setUnderlying(filter0.getHealthServlet());
    }

    if (filter0.getOcspServlet() != null) {
      this.ocspServlet = new HttpOcspServlet();
      this.ocspServlet.setUnderlying(filter0.getOcspServlet());
    }

    if (filter0.getMgmtServlet() != null) {
      mgmtServlet = new HttpMgmtServlet();
      mgmtServlet.setUnderlying(filter0.getMgmtServlet());
    }
  } // method init

  @Override
  public void destroy() {
    if (filter0 != null) {
      filter0.destroy();
      filter0 = null;
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
      if (mgmtServlet != null) {
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
