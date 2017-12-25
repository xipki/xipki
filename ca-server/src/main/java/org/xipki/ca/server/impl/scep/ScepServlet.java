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

package org.xipki.ca.server.impl.scep;

import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.FORBIDDEN;
import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;
import static io.netty.handler.codec.http.HttpResponseStatus.METHOD_NOT_ALLOWED;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
import static io.netty.handler.codec.http.HttpResponseStatus.SERVICE_UNAVAILABLE;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;

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
import org.xipki.ca.server.impl.CaAuditConstants;
import org.xipki.ca.server.impl.CaManagerImpl;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.common.util.Base64;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.RandomUtil;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.util.ScepConstants;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.ext
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepServlet extends AbstractHttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(ScepServlet.class);

    private static final String CGI_PROGRAM = "/pkiclient.exe";

    private static final int CGI_PROGRAM_LEN = CGI_PROGRAM.length();

    private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

    private AuditServiceRegister auditServiceRegister;

    private CaManagerImpl responderManager;

    public ScepServlet() {
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
            return createErrorResponse(version, METHOD_NOT_ALLOWED);
        }

        String scepName = null;
        String certProfileName = null;
        if (servletUri.path().length() > 1) {
            String scepPath = servletUri.path();
            if (scepPath.endsWith(CGI_PROGRAM)) {
                // skip also the first char (which is always '/')
                String path = scepPath.substring(1, scepPath.length() - CGI_PROGRAM_LEN);
                String[] tokens = path.split("/");
                if (tokens.length == 2) {
                    scepName = tokens[0];
                    certProfileName = tokens[1].toUpperCase();
                }
            } // end if
        } // end if

        if (scepName == null || certProfileName == null) {
            return createErrorResponse(version, NOT_FOUND);
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
                return createErrorResponse(version, INTERNAL_SERVER_ERROR);
            }

            Scep responder = responderManager.getScep(scepName);
            if (responder == null || responder.status() != CaStatus.ACTIVE
                    || !responder.supportsCertProfile(certProfileName)) {
                auditMessage = "unknown SCEP '" + scepName + "/" + certProfileName + "'";
                LOG.warn(auditMessage);

                auditStatus = AuditStatus.FAILED;
                return createErrorResponse(version, NOT_FOUND);
            }

            String operation = servletUri.parameter("operation");
            event.addEventData(CaAuditConstants.NAME_SCEP_operation, operation);

            if ("PKIOperation".equalsIgnoreCase(operation)) {
                CMSSignedData reqMessage;
                // parse the request
                try {
                    byte[] content;
                    if (viaPost) {
                        content = readContent(request);
                    } else {
                        String b64 = servletUri.parameter("message");
                        content = Base64.decode(b64);
                    }

                    reqMessage = new CMSSignedData(content);
                } catch (Exception ex) {
                    final String msg = "invalid request";
                    LogUtil.error(LOG, ex, msg);
                    auditMessage = msg;
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, BAD_REQUEST);
                }

                ContentInfo ci;
                try {
                    ci = responder.servicePkiOperation(reqMessage, certProfileName, msgId, event);
                } catch (MessageDecodingException ex) {
                    final String msg = "could not decrypt and/or verify the request";
                    LogUtil.error(LOG, ex, msg);
                    auditMessage = msg;
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, BAD_REQUEST);
                } catch (OperationException ex) {
                    ErrorCode code = ex.errorCode();

                    HttpResponseStatus httpCode;
                    switch (code) {
                    case ALREADY_ISSUED:
                    case CERT_REVOKED:
                    case CERT_UNREVOKED:
                        httpCode = FORBIDDEN;
                        break;
                    case BAD_CERT_TEMPLATE:
                    case BAD_REQUEST:
                    case BAD_POP:
                    case INVALID_EXTENSION:
                    case UNKNOWN_CERT:
                    case UNKNOWN_CERT_PROFILE:
                        httpCode = BAD_REQUEST;
                        break;
                    case NOT_PERMITTED:
                        httpCode = UNAUTHORIZED;
                        break;
                    case SYSTEM_UNAVAILABLE:
                        httpCode = SERVICE_UNAVAILABLE;
                        break;
                    case CRL_FAILURE:
                    case DATABASE_FAILURE:
                    case SYSTEM_FAILURE:
                        httpCode = INTERNAL_SERVER_ERROR;
                        break;
                    default:
                        httpCode = INTERNAL_SERVER_ERROR;
                        break;
                    }

                    auditMessage = ex.getMessage();
                    LogUtil.error(LOG, ex, auditMessage);
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, httpCode);
                }

                byte[] bodyBytes = ci.getEncoded();
                return createOKResponse(version, CT_RESPONSE, bodyBytes);
            } else if (Operation.GetCACaps.code().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] caCapsBytes = responder.caCaps().bytes();
                return createOKResponse(version, ScepConstants.CT_TEXT_PLAIN, caCapsBytes);
            } else if (Operation.GetCACert.code().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] respBytes = responder.caCertResp().bytes();
                return createOKResponse(version, ScepConstants.CT_X509_CA_RA_CERT, respBytes);
            } else if (Operation.GetNextCACert.code().equalsIgnoreCase(operation)) {
                auditMessage = "SCEP operation '" + operation + "' is not permitted";
                auditStatus = AuditStatus.FAILED;
                return createErrorResponse(version, FORBIDDEN);
            } else {
                auditMessage = "unknown SCEP operation '" + operation + "'";
                auditStatus = AuditStatus.FAILED;
                return createErrorResponse(version, BAD_REQUEST);
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
            return createErrorResponse(version, INTERNAL_SERVER_ERROR);
        } finally {
            audit(auditService, event, auditLevel, auditStatus, auditMessage);
        }
    } // method service

    protected PKIMessage generatePkiMessage(final InputStream is) throws IOException {
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

    public void setResponderManager(final CaManagerImpl responderManager) {
        this.responderManager = responderManager;
    }

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    private static void audit(final AuditService auditService, final AuditEvent event,
            final AuditLevel auditLevel, final AuditStatus auditStatus, final String auditMessage) {
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

}
