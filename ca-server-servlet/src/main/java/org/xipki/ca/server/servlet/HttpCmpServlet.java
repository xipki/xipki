/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.servlet;

import java.io.EOFException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.server.api.CaAuditConstants;
import org.xipki.ca.server.api.ResponderManager;
import org.xipki.ca.server.api.X509CaCmpResponder;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpCmpServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;

  private static final Logger LOG = LoggerFactory.getLogger(HttpCmpServlet.class);

  private static final String CT_REQUEST = "application/pkixcmp";

  private static final String CT_RESPONSE = "application/pkixcmp";

  public HttpCmpServlet() {
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    AuditServiceRegister auditServiceRegister = ServletHelper.getAuditServiceRegister();
    if (auditServiceRegister == null) {
      LOG.error("ServletHelper.auditServiceRegister not configured");
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return;
    }

    ResponderManager responderManager = ServletHelper.getResponderManager();
    if (responderManager == null) {
      LOG.error("ServletHelper.responderManager not configured");
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return;
    }

    X509Certificate clientCert = ClientCertCache.getTlsClientCert(req);
    AuditService auditService = auditServiceRegister.getAuditService();
    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_PERF);
    event.addEventData(CaAuditConstants.NAME_reqType, RequestType.CMP.name());

    AuditLevel auditLevel = AuditLevel.INFO;
    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    String auditMessage = null;
    try {
      String reqContentType = req.getHeader("Content-Type");
      if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
        String message = "unsupported media type " + reqContentType;
        throw new HttpRespAuditException(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
            message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      String caName = null;
      X509CaCmpResponder responder = null;
      String path = StringUtil.getRelativeRequestUri(
          req.getServletPath(), req.getRequestURI());
      if (path.length() > 1) {
        // skip the first char which is always '/'
        String caAlias = path.substring(1);
        caName = responderManager.getCaNameForAlias(caAlias);
        if (caName == null) {
          caName = caAlias.toLowerCase();
        }
        responder = responderManager.getX509CaResponder(caName);
      }

      if (caName == null || responder == null || !responder.isOnService()) {
        String message;
        if (caName == null) {
          message = "no CA is specified";
        } else if (responder == null) {
          message = "unknown CA '" + caName + "'";
        } else {
          message = "CA '" + caName + "' is out of service";
        }
        LOG.warn(message);
        throw new HttpRespAuditException(HttpServletResponse.SC_NOT_FOUND, message,
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      event.addEventData(CaAuditConstants.NAME_ca, responder.getCaName());

      byte[] reqContent = IoUtil.read(req.getInputStream());
      PKIMessage pkiReq;
      try {
        pkiReq = PKIMessage.getInstance(reqContent);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "could not parse the request (PKIMessage)");
        throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST,
            "bad request", AuditLevel.INFO, AuditStatus.FAILED);
      }

      PKIMessage pkiResp = responder.processPkiMessage(pkiReq, clientCert, event);
      byte[] encodedPkiResp = pkiResp.getEncoded();

      resp.setContentType(CT_RESPONSE);
      resp.setContentLength(encodedPkiResp.length);
      resp.getOutputStream().write(encodedPkiResp);
    } catch (HttpRespAuditException ex) {
      auditStatus = ex.getAuditStatus();
      auditLevel = ex.getAuditLevel();
      auditMessage = ex.getAuditMessage();
      sendError(resp, ex.getHttpStatus());
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }
      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      auditMessage = "internal error";
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      resp.flushBuffer();
      audit(auditService, event, auditLevel, auditStatus, auditMessage);
    }
  } // method service

  private static void audit(AuditService auditService, AuditEvent event,
      AuditLevel auditLevel, AuditStatus auditStatus, String auditMessage) {
    if (auditLevel != null) {
      event.setLevel(auditLevel);
    }

    if (auditStatus != null) {
      event.setStatus(auditStatus);
    }

    if (auditMessage != null) {
      event.addEventData(CaAuditConstants.NAME_message, auditMessage);
    }

    event.finish();
    auditService.logEvent(event);
  } // method audit

  private static void sendError(HttpServletResponse resp, int status) {
    resp.setStatus(status);
    resp.setContentLength(0);
  }

}
