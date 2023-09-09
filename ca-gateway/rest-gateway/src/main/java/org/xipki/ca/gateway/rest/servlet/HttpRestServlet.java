// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.RestResponse;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.ca.gateway.servlet.HttpRequestMetadataRetrieverImpl;
import org.xipki.ca.gateway.servlet.ServletHelper;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * REST servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HttpRestServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpRestServlet.class);

  private boolean logReqResp;

  private RestResponder responder;

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public void setResponder(RestResponder responder) {
    this.responder = Args.notNull(responder, "responder");
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    service0(req, resp, false);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    service0(req, resp, true);
  }

  private void service0(HttpServletRequest req, HttpServletResponse resp, boolean viaPost)
      throws IOException {
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent();
    event.setApplicationName("rest-gw");
    try {
      String path = req.getServletPath();
      byte[] requestBytes = viaPost ? IoUtil.readAndClose(req.getInputStream()) : null;

      RestResponse restResp = responder.service(path, requestBytes, new HttpRequestMetadataRetrieverImpl(req), event);
      restResp.fillResponse(resp);

      ServletHelper.logReqResp("REST Gateway", LOG, logReqResp, viaPost, req, requestBytes, restResp.getBody());

      if (event.getStatus() == null) {
        event.setStatus(AuditStatus.SUCCESSFUL);
      }
    } catch (RuntimeException ex) {
      event.setStatus(AuditStatus.FAILED);
      event.setLevel(AuditLevel.ERROR);
      LOG.error("RuntimeException thrown, this should not happen!", ex);
      resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      event.finish();
      auditService.logEvent(event);
      GatewayUtil.logAuditEvent(LOG, event);
    }
  } // method service0

}
