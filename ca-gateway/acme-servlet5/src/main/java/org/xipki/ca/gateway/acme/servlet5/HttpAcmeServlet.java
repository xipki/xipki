// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.servlet5;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ca.gateway.acme.servlet.HttpAcmeServlet0;
import org.xipki.servlet5.HttpRequestMetadataRetrieverImpl;
import org.xipki.servlet5.ServletHelper;
import org.xipki.util.http.RestResponse;

import java.io.IOException;

/**
 * ACME servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */

public class HttpAcmeServlet extends HttpServlet {

  private HttpAcmeServlet0 underlying;

  public void setUnderlying(HttpAcmeServlet0 underlying) {
    this.underlying = underlying;
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    RestResponse restResp = underlying.doGet(new HttpRequestMetadataRetrieverImpl(req));
    ServletHelper.fillResponse(restResp, resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    RestResponse restResp = underlying.doPost(new HttpRequestMetadataRetrieverImpl(req), req.getInputStream());
    ServletHelper.fillResponse(restResp, resp);
  }

}
