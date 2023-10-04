// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet5;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ca.gateway.rest.servlet.HttpRestServlet0;
import org.xipki.servlet5.ServletHelper;
import org.xipki.servlet5.XiHttpRequestImpl;

import java.io.IOException;

/**
 * REST servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HttpRestServlet extends HttpServlet {

  private HttpRestServlet0 underlying;

  public void setUnderlying(HttpRestServlet0 underlying) {
    this.underlying = underlying;
  }

  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    ServletHelper.fillResponse(underlying.doGet(new XiHttpRequestImpl(req)), resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    ServletHelper.fillResponse(underlying.doPost(new XiHttpRequestImpl(req)), resp);
  }

}