// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet3;

import org.xipki.ca.gateway.rest.servlet.ProtocolServletFilter0;
import org.xipki.util.exception.ServletException0;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * REST Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter implements Filter {

  private HttpRestServlet servlet;

  private ProtocolServletFilter0 filter0;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    try {
      filter0 = new ProtocolServletFilter0();
    } catch (ServletException0 ex) {
      throw new ServletException(ex);
    }

    servlet = new HttpRestServlet();
    servlet.setUnderlying(filter0.getServlet());
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
