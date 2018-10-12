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

package org.xipki.ca.server.netty;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.server.api.CaAuditConstants;
import org.xipki.ca.server.api.ResponderManager;
import org.xipki.ca.server.api.ScepResponder;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.util.ScepConstants;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;
import org.xipki.util.RandomUtil;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpScepServlet extends AbstractHttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpScepServlet.class);

  private static final String CGI_PROGRAM = "/pkiclient.exe";

  private static final int CGI_PROGRAM_LEN = CGI_PROGRAM.length();

  private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

  private AuditServiceRegister auditServiceRegister;

  private ResponderManager responderManager;

  public HttpScepServlet() {
  }

  @Override
  public boolean needsTlsSessionInfo() {
    return false;
  }

  @Override
  public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
      SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) throws Exception {
    HttpVersion version = request.protocolVersion();
    HttpMethod method = request.method();

    boolean viaPost;
    if (method == HttpMethod.POST) {
      viaPost = true;
    } else if (method == HttpMethod.GET) {
      viaPost = false;
    } else {
      return createErrorResponse(version, HttpResponseStatus.METHOD_NOT_ALLOWED);
    }

    String caAlias = null;
    String certprofileName = null;
    if (servletUri.getPath().length() > 1) {
      String scepPath = servletUri.getPath();
      if (scepPath.endsWith(CGI_PROGRAM)) {
        // skip also the first char (which is always '/')
        String path = scepPath.substring(1, scepPath.length() - CGI_PROGRAM_LEN);
        String[] tokens = path.split("/");
        if (tokens.length == 2) {
          caAlias = tokens[0];
          certprofileName = tokens[1].toLowerCase();
        }
      } // end if
    } // end if

    if (caAlias == null || certprofileName == null) {
      return createErrorResponse(version, HttpResponseStatus.NOT_FOUND);
    }

    AuditService auditService = auditServiceRegister.getAuditService();
    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName("SCEP");
    event.setName(CaAuditConstants.NAME_perf);
    event.addEventData(CaAuditConstants.NAME_SCEP_name, caAlias + "/" + certprofileName);
    event.addEventData(CaAuditConstants.NAME_req_type, RequestType.SCEP.name());

    String msgId = RandomUtil.nextHexLong();
    event.addEventData(CaAuditConstants.NAME_mid, msgId);

    AuditLevel auditLevel = AuditLevel.INFO;
    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    String auditMessage = null;

    try {
      if (responderManager == null) {
        auditMessage = "responderManager in servlet not configured";
        LOG.error(auditMessage);
        auditLevel = AuditLevel.ERROR;
        auditStatus = AuditStatus.FAILED;
        return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
      }

      String caName = responderManager.getCaNameForAlias(caAlias);
      if (caName == null) {
        caName = caAlias.toLowerCase();
      }

      ScepResponder responder = responderManager.getScepResponder(caName);
      if (responder == null || !responder.isOnService()) {
        auditMessage = "unknown SCEP '" + caAlias + "/" + certprofileName + "'";
        LOG.warn(auditMessage);
        auditLevel = AuditLevel.ERROR;
        auditStatus = AuditStatus.FAILED;
        return createErrorResponse(version, HttpResponseStatus.NOT_FOUND);
      }

      String operation = servletUri.getParameter("operation");
      event.addEventData(CaAuditConstants.NAME_SCEP_operation, operation);

      if ("PKIOperation".equalsIgnoreCase(operation)) {
        CMSSignedData reqMessage;
        // parse the request
        try {
          byte[] content;
          if (viaPost) {
            content = readContent(request);
          } else {
            String b64 = servletUri.getParameter("message");
            content = Base64.decode(b64);
          }

          reqMessage = new CMSSignedData(content);
        } catch (Exception ex) {
          final String msg = "invalid request";
          LogUtil.error(LOG, ex, msg);
          auditMessage = msg;
          auditStatus = AuditStatus.FAILED;
          return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
        }

        ContentInfo ci;
        try {
          ci = responder.servicePkiOperation(reqMessage, certprofileName, msgId, event);
        } catch (MessageDecodingException ex) {
          final String msg = "could not decrypt and/or verify the request";
          LogUtil.error(LOG, ex, msg);
          auditMessage = msg;
          auditStatus = AuditStatus.FAILED;
          return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
        } catch (OperationException ex) {
          ErrorCode code = ex.getErrorCode();

          HttpResponseStatus httpCode;
          switch (code) {
            case ALREADY_ISSUED:
            case CERT_REVOKED:
            case CERT_UNREVOKED:
              httpCode = HttpResponseStatus.FORBIDDEN;
              break;
            case BAD_CERT_TEMPLATE:
            case BAD_REQUEST:
            case BAD_POP:
            case INVALID_EXTENSION:
            case UNKNOWN_CERT:
            case UNKNOWN_CERT_PROFILE:
              httpCode = HttpResponseStatus.BAD_REQUEST;
              break;
            case NOT_PERMITTED:
              httpCode = HttpResponseStatus.UNAUTHORIZED;
              break;
            case SYSTEM_UNAVAILABLE:
              httpCode = HttpResponseStatus.SERVICE_UNAVAILABLE;
              break;
            case CRL_FAILURE:
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
              httpCode = HttpResponseStatus.INTERNAL_SERVER_ERROR;
              break;
            default:
              httpCode = HttpResponseStatus.INTERNAL_SERVER_ERROR;
              break;
          }

          auditMessage = ex.getMessage();
          LogUtil.error(LOG, ex, auditMessage);
          auditStatus = AuditStatus.FAILED;
          return createErrorResponse(version, httpCode);
        }

        byte[] bodyBytes = ci.getEncoded();
        return createOKResponse(version, CT_RESPONSE, bodyBytes);
      } else if (Operation.GetCACaps.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        byte[] caCapsBytes = responder.getCaCaps().getBytes();
        return createOKResponse(version, ScepConstants.CT_TEXT_PLAIN, caCapsBytes);
      } else if (Operation.GetCACert.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        byte[] respBytes = responder.getCaCertResp().getBytes();
        return createOKResponse(version, ScepConstants.CT_X509_CA_RA_CERT, respBytes);
      } else if (Operation.GetNextCACert.getCode().equalsIgnoreCase(operation)) {
        auditMessage = "SCEP operation '" + operation + "' is not permitted";
        auditStatus = AuditStatus.FAILED;
        return createErrorResponse(version, HttpResponseStatus.FORBIDDEN);
      } else {
        auditMessage = "unknown SCEP operation '" + operation + "'";
        auditStatus = AuditStatus.FAILED;
        return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
      }

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
      return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
    } finally {
      audit(auditService, event, auditLevel, auditStatus, auditMessage);
    }
  } // method service

  protected PKIMessage generatePkiMessage(InputStream is) throws IOException {
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
  } // method generatePKIMessage

  public void setResponderManager(ResponderManager responderManager) {
    this.responderManager = responderManager;
  }

  public void setAuditServiceRegister(AuditServiceRegister auditServiceRegister) {
    this.auditServiceRegister = auditServiceRegister;
  }

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

  @Override
  public int getMaxUriSize() {
    return 200;
  }

  @Override
  public int getMaxRequestSize() {
    return 4096;
  }

}
