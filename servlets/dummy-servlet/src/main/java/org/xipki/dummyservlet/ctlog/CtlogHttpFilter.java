// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.dummyservlet.ctlog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.extra.http.HttpStatusCode;
import org.xipki.util.extra.http.XiHttpFilter;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.extra.http.XiHttpResponse;

import java.io.IOException;

/**
 * Dummy CRL ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CtlogHttpFilter implements XiHttpFilter {

  private static final Logger LOG =
      LoggerFactory.getLogger(CtlogHttpFilter.class);

  private final CtLogServlet rsa;

  private final CtLogServlet ec;

  public CtlogHttpFilter() {
    this.rsa = new CtLogServlet.RSACtLogServlet();
    this.ec = new CtLogServlet.ECCtLogServlet();
  }

  @Override
  public void destroy() {
  }

  @Override
  public void doFilter(XiHttpRequest req, XiHttpResponse resp)
      throws IOException {
    String method = req.getMethod();
    if (!"POST".equalsIgnoreCase(method)) {
      LOG.warn("method {} not allowed", method);
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
      return;
    }

    String path = req.getServletPath();
    if (path.startsWith("/ctlogrsa/ct/v1/add-pre-chain/")) {
      rsa.doPost(req).fillResponse(resp);
    } else if (path.startsWith("/ctlogec/ct/v1/add-pre-chain/")) {
      ec.doPost(req).fillResponse(resp);
    } else {
      LOG.warn("unknown servlet path {}", path);
      resp.sendError(HttpStatusCode.SC_NOT_FOUND);
    }
  }

}
