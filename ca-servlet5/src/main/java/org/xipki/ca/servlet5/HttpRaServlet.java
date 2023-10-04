// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.servlet5;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ca.server.servlet.HttpRaServlet0;
import org.xipki.servlet5.ServletHelper;
import org.xipki.servlet5.XiHttpRequestImpl;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * REST API exception.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HttpRaServlet extends HttpServlet {

  private HttpRaServlet0 underlying;

  public void setUnderlying(HttpRaServlet0 underlying) {
    this.underlying = Args.notNull(underlying, "underlying");
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    try {
      ServletHelper.fillResponse(underlying.doGet(new XiHttpRequestImpl(request)), response);
    } finally {
      response.flushBuffer();
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    try {
      ServletHelper.fillResponse(underlying.doPost(new XiHttpRequestImpl(request)), response);
    } finally {
      response.flushBuffer();
    }
  }

}
