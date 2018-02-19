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
import java.io.InputStream;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.xipki.ca.server.api.CmpResponderManager;
import org.xipki.ca.server.api.Scep;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.RandomUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.util.ScepConstants;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.ext
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpScepServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = LoggerFactory.getLogger(HttpScepServlet.class);

    private static final String CGI_PROGRAM = "/pkiclient.exe";

    private static final int CGI_PROGRAM_LEN = CGI_PROGRAM.length();

    private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

    private AuditServiceRegister auditServiceRegister;

    private CmpResponderManager responderManager;

    public HttpScepServlet() {
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

    private void service0(HttpServletRequest req, HttpServletResponse resp, boolean viaPost)
            throws ServletException, IOException {
        String path = StringUtil.getRelativeRequestUri(req.getServletPath(),
                req.getRequestURI());

        String scepName = null;
        String certProfileName = null;
        if (path.length() > 1) {
            String scepPath = path;
            if (scepPath.endsWith(CGI_PROGRAM)) {
                // skip also the first char (which is always '/')
                String tpath = scepPath.substring(1, scepPath.length() - CGI_PROGRAM_LEN);
                String[] tokens = tpath.split("/");
                if (tokens.length == 2) {
                    scepName = tokens[0];
                    certProfileName = tokens[1].toLowerCase();
                }
            } // end if
        } // end if

        if (scepName == null || certProfileName == null) {
            sendError(resp, HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        AuditService auditService = auditServiceRegister.getAuditService();
        AuditEvent event = new AuditEvent(new Date());
        event.setApplicationName("SCEP");
        event.setName(CaAuditConstants.NAME_PERF);
        event.addEventData(CaAuditConstants.NAME_SCEP_name, scepName + "/" + certProfileName);
        event.addEventData(CaAuditConstants.NAME_reqType, RequestType.SCEP.name());

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
                sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }

            Scep responder = responderManager.getScep(scepName);
            if (responder == null || !responder.isOnService()
                    || !responder.supportsCertProfile(certProfileName)) {
                auditMessage = "unknown SCEP '" + scepName + "/" + certProfileName + "'";
                LOG.warn(auditMessage);

                auditStatus = AuditStatus.FAILED;
                sendError(resp, HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            String operation = req.getParameter("operation");
            event.addEventData(CaAuditConstants.NAME_SCEP_operation, operation);

            if ("PKIOperation".equalsIgnoreCase(operation)) {
                CMSSignedData reqMessage;
                // parse the request
                try {
                    byte[] content;
                    if (viaPost) {
                        content = IoUtil.read(req.getInputStream());
                    } else {
                        String b64 = req.getParameter("message");
                        content = Base64.decode(b64);
                    }

                    reqMessage = new CMSSignedData(content);
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
                    ci = responder.servicePkiOperation(reqMessage, certProfileName, msgId, event);
                } catch (MessageDecodingException ex) {
                    final String msg = "could not decrypt and/or verify the request";
                    LogUtil.error(LOG, ex, msg);
                    auditMessage = msg;
                    auditStatus = AuditStatus.FAILED;
                    sendError(resp, HttpServletResponse.SC_BAD_REQUEST);
                    return;
                } catch (OperationException ex) {
                    ErrorCode code = ex.errorCode();

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

                byte[] bodyBytes = ci.getEncoded();

                sendOKResponse(resp, CT_RESPONSE, bodyBytes);
            } else if (Operation.GetCACaps.code().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] caCapsBytes = responder.caCaps().bytes();
                sendOKResponse(resp, ScepConstants.CT_TEXT_PLAIN, caCapsBytes);
            } else if (Operation.GetCACert.code().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] respBytes = responder.caCertResp().bytes();
                sendOKResponse(resp, ScepConstants.CT_X509_CA_RA_CERT, respBytes);
            } else if (Operation.GetNextCACert.code().equalsIgnoreCase(operation)) {
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

    public void setResponderManager(CmpResponderManager responderManager) {
        this.responderManager = responderManager;
    }

    public void setAuditServiceRegister(AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    private static void audit(AuditService auditService, AuditEvent event,
            AuditLevel auditLevel, AuditStatus auditStatus, String auditMessage) {
        event.setLevel(auditLevel);

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

    // CHECKSTYLE:SKIP
    private static void sendOKResponse(HttpServletResponse resp, String contentType,
            byte[] content) throws IOException {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType(contentType);
        resp.setContentLength(content.length);
        resp.getOutputStream().write(content);
    }

}
