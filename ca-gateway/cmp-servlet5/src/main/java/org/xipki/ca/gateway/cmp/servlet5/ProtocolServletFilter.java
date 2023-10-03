// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet5;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ca.gateway.cmp.servlet.ProtocolServletFilter0;
import org.xipki.util.exception.ServletException0;

import java.io.IOException;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class ProtocolServletFilter implements Filter {

  private HttpCmpServlet servlet;

  private ProtocolServletFilter0 filter0;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    try {
      filter0 = new ProtocolServletFilter0();
    } catch (ServletException0 ex) {
      throw new ServletException(ex);
    }

    if (filter0.getServlet() != null) {
      servlet = new HttpCmpServlet();
      servlet.setUnderlying(filter0.getServlet());
    }
  }

  @Override
  public void destroy() {
    if (filter0 != null) {
      filter0.destroy();
      filter0 = null;
    }
  }

  @Override
  public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    servlet.service(request, response);
  }

}
