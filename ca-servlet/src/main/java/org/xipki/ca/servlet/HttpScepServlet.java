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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.server.CaAuditConstants;
import org.xipki.ca.server.ScepResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.scep.message.MessageDecodingException;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.util.ScepConstants;
import org.xipki.util.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

/**
 * SCEP servlet.
 *
 * <p>URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpScepServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpScepServlet.class);

  private static final String CGI_PROGRAM = "/pkiclient.exe";

  private static final int CGI_PROGRAM_LEN = CGI_PROGRAM.length();

  private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

  private boolean logReqResp;

  private CaManagerImpl responderManager;

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public void setResponderManager(CaManagerImpl responderManager) {
    this.responderManager = Args.notNull(responderManager, "responderManager");
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    service0(req, resp, false);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    service0(req, resp, true);
  }

  private void service0(HttpServletRequest req, HttpServletResponse resp, boolean viaPost) {
    String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
    String caAlias = null;
    String certprofileName = null;
    if (path.length() > 1) {
      String scepPath = path;
      if (scepPath.endsWith(CGI_PROGRAM)) {
        // skip also the first char (which is always '/')
        String tpath = scepPath.substring(1, scepPath.length() - CGI_PROGRAM_LEN);
        String[] tokens = tpath.split("/");
        if (tokens.length == 2) {
          caAlias = tokens[0];
          certprofileName = tokens[1].toLowerCase();
        }
      } // end if
    } // end if

    if (caAlias == null || certprofileName == null) {
      sendError(resp, HttpServletResponse.SC_NOT_FOUND);
      return;
    }

    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName("SCEP");
    event.setName(CaAuditConstants.NAME_perf);
    event.addEventData(CaAuditConstants.Scep.NAME_name, caAlias + "/" + certprofileName);
    event.addEventData(CaAuditConstants.NAME_req_type, RequestType.SCEP.name());

    String msgId = RandomUtil.nextHexLong();
    event.addEventData(CaAuditConstants.NAME_mid, msgId);

    AuditLevel auditLevel = AuditLevel.INFO;
    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    String auditMessage = null;

    try {
      String caName = responderManager.getCaNameForAlias(caAlias);
      if (caName == null) {
        caName = caAlias.toLowerCase();
      }

      ScepResponder responder = responderManager.getScepResponder(caName);
      if (responder == null || !responder.isOnService()) {
        auditMessage = "unknown SCEP '" + caAlias + "/" + certprofileName + "'";
        LOG.warn(auditMessage);

        auditStatus = AuditStatus.FAILED;
        sendError(resp, HttpServletResponse.SC_NOT_FOUND);
        return;
      }

      String operation = req.getParameter("operation");
      event.addEventData(CaAuditConstants.Scep.NAME_operation, operation);

      byte[] requestBytes;
      byte[] respBody;
      String contentType;

      if ("PKIOperation".equalsIgnoreCase(operation)) {
        CMSSignedData reqMessage;
        // parse the request
        try {
          if (viaPost) {
            requestBytes = IoUtil.read(req.getInputStream());
          } else {
            String b64 = req.getParameter("message");
            requestBytes = Base64.decode(b64);
          }

          reqMessage = new CMSSignedData(requestBytes);
        } catch (Exception ex) {
          final String msg = "invalid request";
          LogUtil.error(LOG, ex, msg);
          auditMessage = msg;
          auditStatus = AuditStatus.FAILED;
          sendError(resp, HttpServletResponse.SC_BAD_REQUEST);
          return;
        }

        ContentInfo ci;
        try {
          ci = responder.servicePkiOperation(reqMessage, certprofileName, msgId, event);
        } catch (MessageDecodingException ex) {
          final String msg = "could not decrypt and/or verify the request";
          LogUtil.error(LOG, ex, msg);
          auditMessage = msg;
          auditStatus = AuditStatus.FAILED;
          sendError(resp, HttpServletResponse.SC_BAD_REQUEST);
          return;
        } catch (OperationException ex) {
          ErrorCode code = ex.getErrorCode();

          int httpCode;
          switch (code) {
            case ALREADY_ISSUED:
            case CERT_REVOKED:
            case CERT_UNREVOKED:
              httpCode = HttpServletResponse.SC_FORBIDDEN;
              break;
            case BAD_CERT_TEMPLATE:
            case BAD_REQUEST:
            case BAD_POP:
            case INVALID_EXTENSION:
            case UNKNOWN_CERT:
            case UNKNOWN_CERT_PROFILE:
              httpCode = HttpServletResponse.SC_BAD_REQUEST;
              break;
            case NOT_PERMITTED:
              httpCode = HttpServletResponse.SC_UNAUTHORIZED;
              break;
            case SYSTEM_UNAVAILABLE:
              httpCode = HttpServletResponse.SC_SERVICE_UNAVAILABLE;
              break;
            case CRL_FAILURE:
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
              httpCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
              break;
            default:
              httpCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
              break;
          }

          auditMessage = ex.getMessage();
          LogUtil.error(LOG, ex, auditMessage);
          auditStatus = AuditStatus.FAILED;
          sendError(resp, httpCode);
          return;
        }

        respBody = ci.getEncoded();
        contentType = CT_RESPONSE;
      } else if (Operation.GetCACaps.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        requestBytes = null;
        contentType = ScepConstants.CT_TEXT_PLAIN;
        respBody = responder.getCaCaps().getBytes();
      } else if (Operation.GetCACert.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        requestBytes = null;
        contentType = ScepConstants.CT_X509_CA_RA_CERT;
        respBody = responder.getCaCertResp().getBytes();
      } else if (Operation.GetNextCACert.getCode().equalsIgnoreCase(operation)) {
        auditMessage = "SCEP operation '" + operation + "' is not permitted";
        auditStatus = AuditStatus.FAILED;
        sendError(resp, HttpServletResponse.SC_FORBIDDEN);
        return;
      } else {
        auditMessage = "unknown SCEP operation '" + operation + "'";
        auditStatus = AuditStatus.FAILED;
        sendError(resp, HttpServletResponse.SC_BAD_REQUEST);
        return;
      }

      if (logReqResp && LOG.isDebugEnabled()) {
        if (viaPost) {
          LOG.debug("HTTP POST CA SCEP path: {}\nRequest:\n{}\nResponse:\n{}",
              req.getRequestURI(),
              LogUtil.base64Encode(requestBytes), LogUtil.base64Encode(respBody));
        } else {
          LOG.debug("HTTP GET CA SCEP path: {}\nResponse:\n{}", req.getRequestURI(),
              LogUtil.base64Encode(respBody));
        }
      }

      sendOKResponse(resp, contentType, respBody);
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        final String msg = "connection reset by peer";
        if (LOG.isWarnEnabled()) {
          LogUtil.warn(LOG, th, msg);
        }
        LOG.debug(msg, th);
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }

      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      auditMessage = "internal error";
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      audit(auditService, event, auditLevel, auditStatus, auditMessage);
    }
  } // method service0

  protected PKIMessage generatePkiMessage(InputStream is)
      throws IOException {
    ASN1InputStream asn1Stream = new ASN1InputStream(is);

    try {
      return PKIMessage.getInstance(asn1Stream.readObject());
    } finally {
      try {
        asn1Stream.close();
      } catch (Exception ex) {
        LOG.error("could not close ASN1 stream: {}", asn1Stream);
      }
    }
  } // method generatePkiMessage

  private static void audit(AuditService auditService, AuditEvent event,
      AuditLevel auditLevel, AuditStatus auditStatus, String auditMessage) {
    AuditLevel curLevel = event.getLevel();
    if (curLevel == null) {
      event.setLevel(auditLevel);
    } else if (curLevel.getValue() > auditLevel.getValue()) {
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
  } // method sendError

  private static void sendOKResponse(HttpServletResponse resp, String contentType, byte[] content)
      throws IOException {
    resp.setStatus(HttpServletResponse.SC_OK);
    resp.setContentType(contentType);
    resp.setContentLength(content.length);
    resp.getOutputStream().write(content);
  } // method sendOKResponse

}
