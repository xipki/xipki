// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet5;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ca.gateway.cmp.servlet.HttpCmpServlet0;
import org.xipki.servlet5.ServletHelper;
import org.xipki.servlet5.XiHttpRequestImpl;

import java.io.IOException;

/**
 * CMP servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class HttpCmpServlet extends HttpServlet {

  private HttpCmpServlet0 underlying;

  public void setUnderlying(HttpCmpServlet0 underlying) {
    this.underlying = underlying;
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    ServletHelper.fillResponse(underlying.doPost(new XiHttpRequestImpl(req)), resp);
  }

}
