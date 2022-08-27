/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.gateway.cmp.servlet;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.ca.gateway.servlet.HttpRespAuditException;
import org.xipki.ca.gateway.servlet.ServletHelper;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.EOFException;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * CMP servlet.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class HttpCmpServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpCmpServlet.class);

  private static final String CT_REQUEST = "application/pkixcmp";

  private static final String CT_RESPONSE = "application/pkixcmp";

  private boolean logReqResp;

  private CmpResponder responder;

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public void setResponder(CmpResponder responder) {
    this.responder = Args.notNull(responder, "responder");
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    X509Cert clientCert = ServletHelper.getTlsClientCert(req);
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_perf);

    try {
      String reqContentType = req.getHeader("Content-Type");
      if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
        String message = "unsupported media type " + reqContentType;
        throw new HttpRespAuditException(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
            message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      String caName = null;
      String path = req.getServletPath();
      if (path.length() > 1) {
        // skip the first char which is always '/'
        String caAlias = path.substring(1);
        if (caName == null) {
          caName = caAlias.toLowerCase();
        }
      }

      if (caName == null) {
        String message = "no CA is specified";
        LOG.warn(message);
        throw new HttpRespAuditException(HttpServletResponse.SC_NOT_FOUND, message,
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      event.addEventData(CaAuditConstants.NAME_ca, caName);

      byte[] requestBytes = IoUtil.read(req.getInputStream());
      PKIMessage pkiReq;
      try {
        pkiReq = PKIMessage.getInstance(requestBytes);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "could not parse the request (PKIMessage)");
        throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST,
            "bad request", AuditLevel.INFO, AuditStatus.FAILED);
      }

      Map<String, String[]> map = req.getParameterMap();
      Map<String, String> parameters = new HashMap<>();
      for (Entry<String, String[]> entry : map.entrySet()) {
        parameters.put(entry.getKey(), entry.getValue()[0]);
      }

      PKIMessage pkiResp = responder.processPkiMessage(caName, pkiReq, clientCert, parameters, event);
      byte[] encodedPkiResp = pkiResp.getEncoded();
      ServletHelper.logReqResp("CMP Gateway", LOG, logReqResp, true, req, requestBytes, encodedPkiResp);

      resp.setContentType(CT_RESPONSE);
      resp.setContentLength(encodedPkiResp.length);
      resp.getOutputStream().write(encodedPkiResp);
    } catch (Throwable th) {
      AuditLevel auditLevel;
      AuditStatus auditStatus;
      String auditMessage;

      int httpStatus = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
      if (th instanceof HttpRespAuditException) {
        HttpRespAuditException hae = (HttpRespAuditException) th;
        httpStatus = hae.getHttpStatus();
        auditStatus = hae.getAuditStatus();
        auditLevel = hae.getAuditLevel();
        auditMessage = hae.getAuditMessage();
      } else {
        auditLevel = AuditLevel.ERROR;
        auditStatus = AuditStatus.FAILED;
        auditMessage = "internal error";
        if (th instanceof EOFException) {
          LogUtil.warn(LOG, th, "connection reset by peer");
        } else {
          LOG.error("Throwable thrown, this should not happen!", th);
        }
      }

      event.setStatus(auditStatus);
      event.setLevel(auditLevel);
      if (auditMessage != null) {
        event.addEventData(CaAuditConstants.NAME_message, auditMessage);
      }

      resp.sendError(httpStatus);
    } finally {
      resp.flushBuffer();
      event.finish();
      auditService.logEvent(event);
      GatewayUtil.logAuditEvent(LOG, event);
    }
  } // method doPost

}
