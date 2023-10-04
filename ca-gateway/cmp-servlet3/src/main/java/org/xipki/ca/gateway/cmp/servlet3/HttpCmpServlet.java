// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet3;

import org.xipki.ca.gateway.cmp.servlet.HttpCmpServlet0;
import org.xipki.servlet3.ServletHelper;
import org.xipki.servlet3.XiHttpRequestImpl;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
