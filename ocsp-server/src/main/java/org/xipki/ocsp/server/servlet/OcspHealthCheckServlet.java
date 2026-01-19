// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.ResponderAndPath;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.http.HttpConstants;
import org.xipki.util.extra.http.HttpResponse;
import org.xipki.util.extra.http.HttpStatusCode;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.extra.http.XiHttpResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * HTTP health check servlet of the OCSP server.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

class OcspHealthCheckServlet {

  private static final Logger LOG =
      LoggerFactory.getLogger(OcspHealthCheckServlet.class);

  private final OcspServer server;

  public OcspHealthCheckServlet(OcspServer server) {
    this.server = Args.notNull(server, "server");
  }

  public void service(XiHttpRequest req, XiHttpResponse resp)
      throws IOException {
    String method = req.getMethod();
    if (!("GET".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method))) {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }
    service0(req).fillResponse(resp);
  }

  private HttpResponse service0(XiHttpRequest req) {

    Map<String, String> headers = new HashMap<>();
    headers.put("Access-Control-Allow-Origin", "*");

    try {
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      ResponderAndPath responderAndPath = server.getResponderForPath(path);
      if (responderAndPath == null) {
        return new HttpResponse(HttpStatusCode.SC_NOT_FOUND, null,
            headers, null);
      }

      boolean healthy = server.healthCheck(responderAndPath.getResponder());
      int status = healthy ? HttpStatusCode.SC_OK
          : HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
      return new HttpResponse(status, null, headers, null);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen", th);
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR,
          null, headers, null);
    }
  }

}
