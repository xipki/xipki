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

package org.xipki.ca.servlet;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.server.CaAuditConstants;
import org.xipki.ca.server.cmp.CmpResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.X509Cert;
import org.xipki.util.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.EOFException;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * CMP servlet.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpCmpServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpCmpServlet.class);

  private static final String CT_REQUEST = "application/pkixcmp";

  private static final String CT_RESPONSE = "application/pkixcmp";

  private boolean logReqResp;

  private CaManagerImpl responderManager;

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public void setResponderManager(CaManagerImpl responderManager) {
    this.responderManager = Args.notNull(responderManager, "responderManager");
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    X509Cert clientCert = TlsHelper.getTlsClientCert(req);
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_perf);
    event.addEventData(CaAuditConstants.NAME_req_type, RequestType.CMP.name());

    try {
      String reqContentType = req.getHeader("Content-Type");
      if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
        String message = "unsupported media type " + reqContentType;
        throw new HttpRespAuditException(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
            message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      String caName = null;
      CmpResponder responder = null;
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
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

      Map<String, String[]> map = req.getParameterMap();
      Map<String, String> parameters = new HashMap<>();
      for (String name : map.keySet()) {
        parameters.put(name, map.get(name)[0]);
      }

      PKIMessage pkiResp = responder.processPkiMessage(pkiReq, clientCert, parameters, event);
      byte[] encodedPkiResp = pkiResp.getEncoded();

      if (logReqResp && LOG.isDebugEnabled()) {
        LOG.debug("HTTP POST CA CMP path: {}\nRequest:\n{}\nResponse:\n{}",
            req.getRequestURI(),
            Base64.encodeToString(reqContent, true),
            Base64.encodeToString(encodedPkiResp, true));
      }

      resp.setContentType(CT_RESPONSE);
      resp.setContentLength(encodedPkiResp.length);
      resp.getOutputStream().write(encodedPkiResp);
    } catch (Throwable th) {
      AuditLevel auditLevel;
      AuditStatus auditStatus;
      String auditMessage;

      if (th instanceof HttpRespAuditException) {
        HttpRespAuditException hae = (HttpRespAuditException) th;
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

      resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      resp.flushBuffer();
      event.finish();
      auditService.logEvent(event);
    }
  } // method doPost

}
