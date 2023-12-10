// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.HttpRespAuditException;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.util.TlsHelper;
import org.xipki.util.Args;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.EOFException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * CMP servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CmpHttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(CmpHttpServlet.class);

  private static final String CT_REQUEST = "application/pkixcmp";

  private static final String CT_RESPONSE = "application/pkixcmp";

  private final boolean logReqResp;

  private final String reverseProxyMode;

  private final CmpResponder responder;

  public CmpHttpServlet(boolean logReqResp, String reverseProxyMode, CmpResponder responder) {
    this.logReqResp = logReqResp;
    this.reverseProxyMode = reverseProxyMode;
    this.responder = Args.notNull(responder, "responder");
  }

  public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String method = req.getMethod();
    if ("POST".equalsIgnoreCase(method)) {
      doPost(req).fillResponse(resp);
    } else {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }
  }

  private HttpResponse doPost(XiHttpRequest req) throws IOException {
    X509Cert clientCert = TlsHelper.getTlsClientCert(req, reverseProxyMode);
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent("cmp-gw");

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
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      if (path.length() > 1) {
        // skip the first char which is always '/'
        caName = path.substring(1).toLowerCase();
      }

      if (caName == null) {
        String message = "no CA is specified";
        LOG.warn(message);
        throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      event.addEventData(CaAuditConstants.NAME_ca, caName);

      requestBytes = IoUtil.readAllBytes(req.getInputStream());
      PKIMessage pkiReq;
      try {
        pkiReq = PKIMessage.getInstance(requestBytes);
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "could not parse the request (PKIMessage)");
        throw new HttpRespAuditException(HttpStatusCode.SC_BAD_REQUEST,
            "bad request", AuditLevel.INFO, AuditStatus.FAILED);
      }

      String certprofile = req.getHeader(BaseCmpResponder.HTTP_HEADER_certprofile);
      String groupEnroll = req.getHeader(BaseCmpResponder.HTTP_HEADER_groupenroll);

      Map<String, String> reqHeaders = null;
      if (certprofile != null || groupEnroll != null) {
        reqHeaders = new HashMap<>(3);
        if (certprofile != null) {
          reqHeaders.put(BaseCmpResponder.HTTP_HEADER_certprofile, certprofile);
        }
        if (groupEnroll != null) {
          reqHeaders.put(BaseCmpResponder.HTTP_HEADER_groupenroll, groupEnroll);
        }
      }

      PKIMessage pkiResp = responder.processPkiMessage(caName, pkiReq, clientCert, reqHeaders, event);
      encodedPkiResp = pkiResp.getEncoded();

      return new HttpResponse(HttpStatusCode.SC_OK, CT_RESPONSE, null, encodedPkiResp);
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

      return new HttpResponse(httpStatus);
    } finally {
      LogUtil.logReqResp("CMP Gateway", LOG, logReqResp, true,
          req.getRequestURI(), requestBytes, encodedPkiResp);

      event.finish();
      auditService.logEvent(event);
      GatewayUtil.logAuditEvent(LOG, event);
    }
  } // method doPost

}
