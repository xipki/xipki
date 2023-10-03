// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.servlet5;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ca.server.servlet.CaServletFilter0;
import org.xipki.util.HttpConstants;
import org.xipki.util.exception.ServletException0;

import java.io.IOException;

/**
 * CA ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CaServletFilter implements Filter {

  private HttpRaServlet raServlet;

  private HttpMgmtServlet mgmtServlet;

  private CaServletFilter0 filter0;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    String licenseFactoryClazz = filterConfig.getInitParameter("licenseFactory");
    try {
      filter0 = new CaServletFilter0(licenseFactoryClazz);
    } catch (ServletException0 e) {
      throw new ServletException(e);
    }

    if (filter0.getRaServlet() != null) {
      this.raServlet = new HttpRaServlet();
      this.raServlet.setUnderlying(filter0.getRaServlet());
    }

    if (filter0.getMgmtServlet() != null) {
      mgmtServlet = new HttpMgmtServlet();
      mgmtServlet.setUnderlying(filter0.getMgmtServlet());
    }
  }

  @Override
  public void destroy() {
    if (filter0 != null) {
      filter0.destroy();
      filter0 = null;
    }
  } // method destroy

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse res = (HttpServletResponse) response;

    String path = req.getServletPath();
    if (path.startsWith("/ra/")) {
      if (raServlet != null) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(3)); // 3 = "/ra".length()
        raServlet.service(req, res);
      } else {
        sendError(res, HttpServletResponse.SC_NOT_FOUND);
      }
    } else if (path.startsWith("/mgmt/")) {
      if (mgmtServlet != null) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/mgmt".length()
        mgmtServlet.service(req, res);
      } else {
        sendError(res, HttpServletResponse.SC_FORBIDDEN);
      }
    } else {
      sendError(res, HttpServletResponse.SC_NOT_FOUND);
    }
  }

  private static void sendError(HttpServletResponse res, int status) {
    res.setStatus(status);
    res.setContentLength(0);
  }

}
