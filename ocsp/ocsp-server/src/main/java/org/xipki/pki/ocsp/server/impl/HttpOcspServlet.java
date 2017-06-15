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

package org.xipki.pki.ocsp.server.impl;

import static io.netty.handler.codec.http.HttpResponseStatus.METHOD_NOT_ALLOWED;

import java.io.EOFException;
import java.util.Date;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.pki.ocsp.server.impl.OcspRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.security.HashAlgoType;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpOcspServlet extends AbstractHttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HttpOcspServlet.class);

    private static final String CT_REQUEST = "application/ocsp-request";

    private static final String CT_RESPONSE = "application/ocsp-response";

    private AuditServiceRegister auditServiceRegister;

    private OcspServer server;

    public HttpOcspServlet() {
    }

    public void setServer(final OcspServer server) {
        this.server = server;
    }

    @Override
    public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) throws Exception {
        HttpVersion version = request.protocolVersion();
        HttpMethod method = request.method();

        boolean viaGet;
        if (method == HttpMethod.GET) {
            viaGet = true;
        } else if (method == HttpMethod.POST) {
            viaGet = false;
        } else {
            return createErrorResponse(version, METHOD_NOT_ALLOWED);
        }

        if (server == null) {
            String message = "responder in servlet not configured";
            LOG.error(message);
            return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
        }

        Responder responder = null;
        String b64OcspReq = null;

        if (viaGet) {
            Object[] objs = server.getServletPathAndResponder(servletUri);
            if (objs != null) {
                String path = servletUri.path();
                String servletPath = (String) objs[0];
                responder = (Responder) objs[1];
                int offset = servletPath.length();
                // GET URI contains the request and must be much longer than 10.
                if (path.length() - offset > 10) {
                    if (path.charAt(offset) == '/') {
                        offset++;
                    }
                    b64OcspReq = servletUri.path().substring(offset);
                }
            }
        } else {
            responder = server.getResponder(servletUri);
        }

        if (responder == null) {
            return createErrorResponse(version, HttpResponseStatus.NOT_FOUND);
        }

        if (viaGet) {
            if (b64OcspReq == null) {
                return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
            } else if (!responder.getRequestOption().supportsHttpGet()) {
                return createErrorResponse(version, HttpResponseStatus.METHOD_NOT_ALLOWED);
            }
        }

        AuditEvent event = null;
        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
        String auditMessage = null;

        AuditService auditService = (auditServiceRegister == null) ? null
                : auditServiceRegister.getAuditService();

        if (responder.getAuditOption() != null) {
            event = new AuditEvent(new Date());
            event.setApplicationName(OcspAuditConstants.APPNAME);
            event.setName(OcspAuditConstants.NAME_PERF);
        }

        try {
            byte[] content;
            if (viaGet) {
                // RFC2560 A.1.1 specifies that request longer than 255 bytes SHOULD be sent by
                // POST, we support GET for longer requests anyway.
                if (b64OcspReq.length() > responder.getRequestOption().getMaxRequestSize()) {
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "request too large";
                    return createErrorResponse(version,
                            HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE);
                }

                // TODO: check whether it is URL decoded
                content = Base64.decode(b64OcspReq);
            } else {
                // accept only "application/ocsp-request" as content type
                String reqContentType = request.headers().get("Content-Type");
                if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "unsupported media type " + reqContentType;
                    return createErrorResponse(version, HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE);
                }

                int contentLen = request.content().readableBytes();
                // request too long
                if (contentLen > responder.getRequestOption().getMaxRequestSize()) {
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "request too large";
                    return createErrorResponse(version,
                            HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE);
                } // if (CT_REQUEST)

                content = readContent(request);
            } // end if (getMethod)

            OCSPRequest ocspRequest;
            try {
                ocspRequest = OCSPRequest.getInstance(content);
            } catch (Exception ex) {
                auditStatus = AuditStatus.FAILED;
                auditMessage = "bad request";

                LogUtil.error(LOG, ex, "could not parse the request (OCSPRequest)");
                return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
            }

            OCSPReq ocspReq = new OCSPReq(ocspRequest);

            OcspRespWithCacheInfo ocspRespWithCacheInfo =
                    server.answer(responder, ocspReq, viaGet, event);
            if (ocspRespWithCacheInfo == null || ocspRespWithCacheInfo.getResponse() == null) {
                auditMessage = "processRequest returned null, this should not happen";
                LOG.error(auditMessage);
                auditLevel = AuditLevel.ERROR;
                auditStatus = AuditStatus.FAILED;
                return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
            }

            OCSPResp resp = ocspRespWithCacheInfo.getResponse();
            byte[] encodedOcspResp = resp.getEncoded();

            FullHttpResponse response = createOKResponse(version, CT_RESPONSE, encodedOcspResp);

            ResponseCacheInfo cacheInfo = ocspRespWithCacheInfo.getCacheInfo();
            if (viaGet && cacheInfo != null) {
                encodedOcspResp = resp.getEncoded();
                long now = System.currentTimeMillis();

                HttpHeaders headers = response.headers();
                // RFC 5019 6.2: Date: The date and time at which the OCSP server generated
                // the HTTP response.
                headers.add("Date", now);
                // RFC 5019 6.2: Last-Modified: date and time at which the OCSP responder
                // last modified the response.
                headers.add("Last-Modified", cacheInfo.getThisUpdate());
                // RFC 5019 6.2: Expires: This date and time will be the same as the
                // nextUpdate time-stamp in the OCSP
                // response itself.
                // This is overridden by max-age on HTTP/1.1 compatible components
                if (cacheInfo.getNextUpdate() != null) {
                    headers.add("Expires", cacheInfo.getNextUpdate());
                }
                // RFC 5019 6.2: This profile RECOMMENDS that the ETag value be the ASCII
                // HEX representation of the SHA1 hash of the OCSPResponse structure.
                headers.add("ETag",
                        new StringBuilder(42).append('\\')
                            .append(HashAlgoType.SHA1.hexHash(encodedOcspResp))
                            .append('\\')
                        .toString());

                // Max age must be in seconds in the cache-control header
                long maxAge;
                if (responder.getResponseOption().getCacheMaxAge() != null) {
                    maxAge = responder.getResponseOption().getCacheMaxAge().longValue();
                } else {
                    maxAge = OcspServer.DFLT_CACHE_MAX_AGE;
                }

                if (cacheInfo.getNextUpdate() != null) {
                    maxAge = Math.min(maxAge,
                            (cacheInfo.getNextUpdate() - cacheInfo.getThisUpdate()) / 1000);
                }

                headers.add("Cache-Control",
                        new StringBuilder(55).append("max-age=").append(maxAge)
                            .append(",public,no-transform,must-revalidate").toString());
            } // end if (ocspRespWithCacheInfo)

            return response;
        } catch (Throwable th) {
            if (th instanceof EOFException) {
                LogUtil.warn(LOG, th, "Connection reset by peer");
            } else {
                LOG.error("Throwable thrown, this should not happen!", th);
            }

            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
            return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
        } finally {
            if (event != null) {
                if (auditLevel != null) {
                    event.setLevel(auditLevel);
                }

                if (auditStatus != null) {
                    event.setStatus(auditStatus);
                }

                if (auditMessage != null) {
                    event.addEventData(OcspAuditConstants.NAME_message, auditMessage);
                }

                event.finish();
                auditService.logEvent(event);
            }
        } // end external try
    } // method processRequest

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = ParamUtil.requireNonNull("auditServiceRegister",
                auditServiceRegister);
    }

}
