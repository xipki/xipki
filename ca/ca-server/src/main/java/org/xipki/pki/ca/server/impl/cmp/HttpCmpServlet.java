/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.server.impl.cmp;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.api.AuditEvent;
import org.xipki.commons.audit.api.AuditLevel;
import org.xipki.commons.audit.api.AuditService;
import org.xipki.commons.audit.api.AuditServiceRegister;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.server.impl.CaAuditConstants;
import org.xipki.pki.ca.server.impl.ClientCertCache;
import org.xipki.pki.ca.server.impl.HttpRespAuditException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpCmpServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HttpCmpServlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_REQUEST = "application/pkixcmp";

    private static final String CT_RESPONSE = "application/pkixcmp";

    private CmpResponderManager responderManager;

    private AuditServiceRegister auditServiceRegister;

    private boolean sslCertInHttpHeader;

    public HttpCmpServlet() {
    }

    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response)
    throws ServletException, IOException {
        X509Certificate clientCert = ClientCertCache.getTlsClientCert(request, sslCertInHttpHeader);

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
                throw new HttpRespAuditException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        message, AuditLevel.ERROR, AuditStatus.FAILED);
            }

            if (!CT_REQUEST.equalsIgnoreCase(request.getContentType())) {
                String message = "unsupported media type " + request.getContentType();
                throw new HttpRespAuditException(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
                        message, AuditLevel.INFO, AuditStatus.FAILED);
            }

            String requestUri = request.getRequestURI();
            String servletPath = request.getServletPath();

            String caName = null;
            X509CaCmpResponder responder = null;
            int len = servletPath.length();
            if (requestUri.length() > len + 1) {
                String caAlias = URLDecoder.decode(requestUri.substring(len + 1), "UTF-8");
                caName = responderManager.getCaNameForAlias(caAlias);
                if (caName == null) {
                    caName = caAlias;
                }
                caName = caName.toUpperCase();
                responder = responderManager.getX509CaCmpResponder(caName);
            }

            if (caName == null || responder == null || !responder.isInService()) {
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

            event.addEventData("CA", responder.getCa().getCaName());

            PKIMessage pkiReq;
            try {
                pkiReq = generatePkiMessage(request.getInputStream());
            } catch (Exception ex) {
                LogUtil.error(LOG, ex, "could not parse the request (PKIMessage)");
                throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST, "bad request",
                        AuditLevel.INFO, AuditStatus.FAILED);
            }

            PKIHeader reqHeader = pkiReq.getHeader();
            ASN1OctetString tid = reqHeader.getTransactionID();
            String tidStr = Base64.toBase64String(tid.getOctets());
            event.addEventData(CaAuditConstants.NAME_tid, tidStr);

            PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
                    reqHeader.getPvno().getValue().intValue(), reqHeader.getRecipient(),
                    reqHeader.getSender());
            respHeader.setTransactionID(tid);

            PKIMessage pkiResp = responder.processPkiMessage(pkiReq, clientCert, tidStr, event);
            response.setContentType(HttpCmpServlet.CT_RESPONSE);
            response.setStatus(HttpServletResponse.SC_OK);
            ASN1OutputStream asn1Out = new ASN1OutputStream(response.getOutputStream());
            asn1Out.writeObject(pkiResp);
            asn1Out.flush();
        } catch (HttpRespAuditException ex) {
            auditStatus = ex.getAuditStatus();
            auditLevel = ex.getAuditLevel();
            auditMessage = ex.getAuditMessage();
            response.setContentLength(0);
            response.setStatus(ex.getHttpStatus());
        } catch (EOFException ex) {
            LogUtil.warn(LOG, ex, "connection reset by peer");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } catch (Throwable th) {
            final String message = "Throwable thrown, this should not happen!";
            LogUtil.error(LOG, th, message);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
        } finally {
            try {
                response.flushBuffer();
            } finally {
                audit(auditService, event, auditLevel, auditStatus, auditMessage);
            }
        }
    } // method doPost

    protected PKIMessage generatePkiMessage(final InputStream is) throws IOException {
        ParamUtil.requireNonNull("is", is);
        ASN1InputStream asn1Stream = new ASN1InputStream(is);

        try {
            return PKIMessage.getInstance(asn1Stream.readObject());
        } finally {
            try {
                asn1Stream.close();
            } catch (Exception ex) {
                LOG.error("could not close ASN1Stream: {}", ex.getMessage());
            }
        }
    }

    public void setResponderManager(final CmpResponderManager responderManager) {
        this.responderManager = responderManager;
    }

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    public void setSslCertInHttpHeader(final boolean sslCertInHttpHeader) {
        this.sslCertInHttpHeader = sslCertInHttpHeader;
    }

    private static void audit(final AuditService auditService, final AuditEvent auditEvent,
            final AuditLevel auditLevel, final AuditStatus auditStatus, final String auditMessage) {
        if (auditLevel != null) {
            auditEvent.setLevel(auditLevel);
        }

        if (auditStatus != null) {
            auditEvent.setStatus(auditStatus);
        }

        if (auditMessage != null) {
            auditEvent.addEventData("message", auditMessage);
        }

        auditEvent.finish();
        auditService.logEvent(auditEvent);
    } // method audit

}
