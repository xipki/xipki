/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.server.impl.cmp;

import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;
import static io.netty.handler.codec.http.HttpResponseStatus.METHOD_NOT_ALLOWED;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
import static io.netty.handler.codec.http.HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE;

import java.io.EOFException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.server.impl.CaAuditConstants;
import org.xipki.ca.server.impl.HttpRespAuditException;
import org.xipki.common.util.LogUtil;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpCmpServlet extends AbstractHttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HttpCmpServlet.class);

    private static final String CT_REQUEST = "application/pkixcmp";

    private static final String CT_RESPONSE = "application/pkixcmp";

    private CmpResponderManager responderManager;

    private AuditServiceRegister auditServiceRegister;

    public HttpCmpServlet() {
    }

    @Override
    public boolean needsTlsSessionInfo() {
        return true;
    }

    @Override
    public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode)
            throws Exception {
        HttpVersion httpVersion = request.protocolVersion();
        HttpMethod method = request.method();
        if (method != HttpMethod.POST) {
            return createErrorResponse(httpVersion, METHOD_NOT_ALLOWED);
        }

        X509Certificate clientCert = getClientCert(request, sslSession, sslReverseProxyMode);
        AuditService auditService = auditServiceRegister.getAuditService();
        AuditEvent event = new AuditEvent(new Date());
        event.setApplicationName(CaAuditConstants.APPNAME);
        event.setName(CaAuditConstants.NAME_PERF);
        event.addEventData(CaAuditConstants.NAME_reqType, RequestType.CMP.name());

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
        String auditMessage = null;
        try {
            if (responderManager == null) {
                String message = "responderManager in servlet not configured";
                LOG.error(message);
                throw new HttpRespAuditException(INTERNAL_SERVER_ERROR,
                        message, AuditLevel.ERROR, AuditStatus.FAILED);
            }

            String reqContentType = request.headers().get("Content-Type");
            if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
                String message = "unsupported media type " + reqContentType;
                throw new HttpRespAuditException(UNSUPPORTED_MEDIA_TYPE,
                        message, AuditLevel.INFO, AuditStatus.FAILED);
            }

            String caName = null;
            X509CaCmpResponder responder = null;
            if (servletUri.path().length() > 1) {
                // skip the first char which is always '/'
                String caAlias = servletUri.path().substring(1);
                caName = responderManager.getCaNameForAlias(caAlias);
                if (caName == null) {
                    caName = caAlias.toUpperCase();
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
                throw new HttpRespAuditException(NOT_FOUND, message,
                        AuditLevel.INFO, AuditStatus.FAILED);
            }

            event.addEventData(CaAuditConstants.NAME_CA, responder.getCa().caIdent().name());

            byte[] reqContent = readContent(request);
            PKIMessage pkiReq;
            try {
                pkiReq = PKIMessage.getInstance(reqContent);
            } catch (Exception ex) {
                LogUtil.error(LOG, ex, "could not parse the request (PKIMessage)");
                throw new HttpRespAuditException(BAD_REQUEST,
                        "bad request", AuditLevel.INFO, AuditStatus.FAILED);
            }

            PKIMessage pkiResp = responder.processPkiMessage(pkiReq, clientCert, event);
            byte[] encodedPkiResp = pkiResp.getEncoded();
            return createOKResponse(httpVersion, CT_RESPONSE, encodedPkiResp);
        } catch (HttpRespAuditException ex) {
            auditStatus = ex.auditStatus();
            auditLevel = ex.auditLevel();
            auditMessage = ex.auditMessage();
            return createErrorResponse(httpVersion, ex.httpStatus());
        } catch (Throwable th) {
            if (th instanceof EOFException) {
                LogUtil.warn(LOG, th, "connection reset by peer");
            } else {
                LOG.error("Throwable thrown, this should not happen!", th);
            }
            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
            return createErrorResponse(httpVersion, INTERNAL_SERVER_ERROR);
        } finally {
            audit(auditService, event, auditLevel, auditStatus, auditMessage);
        }
    } // method service

    public void setResponderManager(final CmpResponderManager responderManager) {
        this.responderManager = responderManager;
    }

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    private static void audit(final AuditService auditService, final AuditEvent event,
            final AuditLevel auditLevel, final AuditStatus auditStatus, final String auditMessage) {
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

}
