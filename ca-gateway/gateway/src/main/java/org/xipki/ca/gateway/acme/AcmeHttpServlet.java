// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.Audits;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;

/**
 * ACME servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */

public class AcmeHttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(AcmeHttpServlet.class);

  private final boolean logReqResp;

  private final AcmeResponder responder;

  public AcmeHttpServlet(boolean logReqResp, AcmeResponder responder) {
    this.logReqResp = logReqResp;
    this.responder = Args.notNull(responder, "responder");
  }

  AcmeResponder getResponder() {
    return responder;
  }

  public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String method = req.getMethod();
    if (!("GET".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method))) {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }
    service0(req, "POST".equalsIgnoreCase(method)).fillResponse(resp);
  }

  private HttpResponse service0(XiHttpRequest req, boolean viaPost) throws IOException {
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent("acme-gw");

    byte[] requestBytes = null;
    HttpResponse httpResp = null;
    try {
      requestBytes = viaPost ? IoUtil.readAllBytes(req.getInputStream()) : null;
      httpResp = responder.service(req, requestBytes, event);
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
      LogUtil.logTextReqResp("ACME Gateway", LOG, logReqResp, viaPost, req.getRequestURI(),
          requestBytes, httpResp == null ? null : httpResp.getBody());

      event.finish();
      auditService.logEvent(event);
      GatewayUtil.logAuditEvent(LOG, event);
    }
  } // method service0

}
