// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;

/**
 * REST servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

class RestHttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(RestHttpServlet.class);

  private final boolean logReqResp;

  private final RestResponder responder;

  public RestHttpServlet(boolean logReqResp, RestResponder responder) {
    this.logReqResp = logReqResp;
    this.responder = Args.notNull(responder, "responder");
  }

  public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String method = req.getMethod();
    if ("GET".equalsIgnoreCase(method)) {
      service0(req, false).fillResponse(resp);
    } else if ("POST".equalsIgnoreCase(method)) {
      service0(req, true).fillResponse(resp);
    } else {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }
  }

  private HttpResponse service0(XiHttpRequest req, boolean viaPost)
      throws IOException {
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent();
    event.setApplicationName("rest-gw");

    byte[] requestBytes = null;
    HttpResponse httpResp = null;
    try {
      String path = req.getServletPath();
      requestBytes = viaPost ? IoUtil.readAllBytes(req.getInputStream()) : null;
      httpResp = responder.service(path, requestBytes, req, event);
      if (event.getStatus() == null) {
        event.setStatus(AuditStatus.SUCCESSFUL);
      }
      return httpResp;
    } catch (RuntimeException ex) {
      event.setStatus(AuditStatus.FAILED);
      event.setLevel(AuditLevel.ERROR);
      LOG.error("RuntimeException thrown, this should not happen!", ex);
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    } finally {
      LogUtil.logReqResp("REST Gateway", LOG, logReqResp, viaPost, req.getRequestURI(),
          requestBytes, httpResp == null ? null : httpResp.getBody());

      event.finish();
      auditService.logEvent(event);
      GatewayUtil.logAuditEvent(LOG, event);
    }
  } // method service0

}
