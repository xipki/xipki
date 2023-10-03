// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.HttpRespAuditException;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.util.HttpRequestMetadataRetriever;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.RestResponse;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * CMP servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class HttpCmpServlet0 {

  private static final Logger LOG = LoggerFactory.getLogger(HttpCmpServlet0.class);

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

  public RestResponse doPost(HttpRequestMetadataRetriever req, InputStream reqStream,
                             Map<String, String> reqHeaders) throws IOException {
    X509Cert clientCert = req.getTlsClientCert();
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent();
    event.setApplicationName("cmp-gw");

    byte[] requestBytes = null;
    byte[] encodedPkiResp = null;

    try {
      String reqContentType = req.getHeader("Content-Type");
      if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
        String message = "unsupported media type " + reqContentType;
        throw new HttpRespAuditException(HttpStatusCode.SC_UNSUPPORTED_MEDIA_TYPE,
            message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      String caName = null;
      String path = req.getServletPath();
      if (path.length() > 1) {
        // skip the first char which is always '/'
        caName = path.substring(1).toLowerCase();
      }

      if (caName == null) {
        String message = "no CA is specified";
        LOG.warn(message);
        throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message,
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      event.addEventData(CaAuditConstants.NAME_ca, caName);

      requestBytes = IoUtil.readAllBytesAndClose(reqStream);
      PKIMessage pkiReq;
      try {
        pkiReq = PKIMessage.getInstance(requestBytes);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "could not parse the request (PKIMessage)");
        throw new HttpRespAuditException(HttpStatusCode.SC_BAD_REQUEST,
            "bad request", AuditLevel.INFO, AuditStatus.FAILED);
      }

      PKIMessage pkiResp = responder.processPkiMessage(caName, pkiReq, clientCert, reqHeaders, event);
      encodedPkiResp = pkiResp.getEncoded();

      return new RestResponse(HttpStatusCode.SC_OK, CT_RESPONSE, null, encodedPkiResp);
    } catch (Throwable th) {
      AuditLevel auditLevel;
      AuditStatus auditStatus;
      String auditMessage;

      int httpStatus = HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
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

      return new RestResponse(httpStatus);
    } finally {
      LogUtil.logReqResp("CMP Gateway", LOG, logReqResp, true,
          req.getRequestURI(), requestBytes, encodedPkiResp);

      event.finish();
      auditService.logEvent(event);
      GatewayUtil.logAuditEvent(LOG, event);
    }
  } // method doPost

}
