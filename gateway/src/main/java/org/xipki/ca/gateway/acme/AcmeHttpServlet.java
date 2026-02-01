// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.audit.AuditLevel;
import org.xipki.util.extra.audit.AuditService;
import org.xipki.util.extra.audit.AuditStatus;
import org.xipki.util.extra.audit.Audits;
import org.xipki.util.extra.http.HttpResponse;
import org.xipki.util.extra.http.HttpStatusCode;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.extra.http.XiHttpResponse;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;

import java.io.IOException;

/**
 * ACME servlet.
 *
 * @author Lijun Liao (xipki)
 */

public class AcmeHttpServlet {

  private static final Logger LOG =
      LoggerFactory.getLogger(AcmeHttpServlet.class);

  private final boolean logReqResp;

  private final AcmeResponder responder;

  public AcmeHttpServlet(boolean logReqResp, AcmeResponder responder) {
    this.logReqResp = logReqResp;
    this.responder = Args.notNull(responder, "responder");
  }

  AcmeResponder responder() {
    return responder;
  }

  public void service(XiHttpRequest req, XiHttpResponse resp)
      throws IOException {
    String method = req.getMethod();
    if (!("GET".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method))) {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }
    service0(req, "POST".equalsIgnoreCase(method)).fillResponse(resp);
  }

  private HttpResponse service0(XiHttpRequest req, boolean viaPost)
      throws IOException {
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent("acme-gw");

    byte[] requestBytes = null;
    HttpResponse httpResp = null;
    try {
      requestBytes = viaPost ? IoUtil.readAllBytes(req.getInputStream()) : null;
      httpResp = responder.service(req, requestBytes, event);
      if (event.status() == null) {
        event.setStatus(AuditStatus.SUCCESSFUL);
      }
      return httpResp;
    } catch (RuntimeException ex) {
      event.setStatus(AuditStatus.FAILED);
      event.setLevel(AuditLevel.ERROR);
      LOG.error("RuntimeException thrown, this should not happen!", ex);
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    } finally {
      LogUtil.logTextReqResp("ACME Gateway", LOG, logReqResp, viaPost,
          req.getRequestURI(), requestBytes,
          httpResp == null ? null : httpResp.body());

      event.finish();
      auditService.logEvent(event);
      GatewayUtil.logAuditEvent(LOG, event);
    }
  } // method service0

}
