// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet3;

import org.xipki.ocsp.server.servlet.HttpMgmtServlet0;
import org.xipki.servlet3.ServletHelper;
import org.xipki.servlet3.XiHttpRequestImpl;
import org.xipki.util.Args;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * REST management servlet of OCSP server.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HttpMgmtServlet extends HttpServlet {

  private HttpMgmtServlet0 underlying;

  public void setUnderlying(HttpMgmtServlet0 underlying) {
    this.underlying = Args.notNull(underlying, "undelying");
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    try {
      ServletHelper.fillResponse(underlying.doPost(new XiHttpRequestImpl(req)), resp);
    } finally {
      resp.flushBuffer();
    }
  }

}