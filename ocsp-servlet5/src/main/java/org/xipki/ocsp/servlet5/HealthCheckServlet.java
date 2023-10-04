// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet5;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ocsp.server.servlet.HealthCheckServlet0;
import org.xipki.servlet5.ServletHelper;
import org.xipki.servlet5.XiHttpRequestImpl;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * HTTP health check servlet of the OCSP server.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HealthCheckServlet extends HttpServlet {

  private HealthCheckServlet0 underlying;

  public void setUnderlying(HealthCheckServlet0 underlying) {
    this.underlying = Args.notNull(underlying, "undelying");
  }

  @Override
  protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
    try {
      ServletHelper.fillResponse(underlying.doGet(new XiHttpRequestImpl(req)), resp);
    } finally {
      resp.flushBuffer();
    }
  } // method doGet

}
