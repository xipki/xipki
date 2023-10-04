// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.OcspServer;
import org.xipki.ocsp.api.ResponderAndPath;
import org.xipki.util.HttpConstants;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.util.HashMap;
import java.util.Map;

import static org.xipki.util.Args.notNull;

/**
 * HTTP health check servlet of the OCSP server.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HealthCheckServlet0 {

  private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet0.class);

  private OcspServer server;

  public void setServer(OcspServer server) {
    this.server = notNull(server, "server");
  }

  public XiHttpResponse doGet(XiHttpRequest req) {
    Map<String, String> headers = new HashMap<>();
    headers.put("Access-Control-Allow-Origin", "*");

    try {
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      ResponderAndPath responderAndPath = server.getResponderForPath(path);
      if (responderAndPath == null) {
        return new XiHttpResponse(HttpStatusCode.SC_NOT_FOUND, null, headers, null);
      }

      boolean healthy = server.healthCheck(responderAndPath.getResponder());
      int status = healthy ? HttpStatusCode.SC_OK : HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
      return new XiHttpResponse(status, null, headers, null);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen", th);
      return new XiHttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR, null, headers, null);
    }
  }

}
