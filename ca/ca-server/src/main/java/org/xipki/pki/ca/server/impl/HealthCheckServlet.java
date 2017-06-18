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

package org.xipki.pki.ca.server.impl;

import static io.netty.handler.codec.http.HttpResponseStatus.METHOD_NOT_ALLOWED;

import java.io.EOFException;

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderManager;
import org.xipki.pki.ca.server.impl.cmp.X509CaCmpResponder;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HealthCheckServlet extends AbstractHttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet.class);

    private static final String CT_RESPONSE = "application/json";

    private CmpResponderManager responderManager;

    public HealthCheckServlet() {
    }

    @Override
    public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) throws Exception {
        FullHttpResponse resp = service0(request, servletUri, sslSession);
        resp.headers().add("Access-Control-Allow-Origin", "*");
        return resp;
    }

    private FullHttpResponse service0(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession) {
        HttpVersion version = request.protocolVersion();
        HttpMethod method = request.method();

        if (method != HttpMethod.GET) {
            return createErrorResponse(version, METHOD_NOT_ALLOWED);
        }

        try {
            if (responderManager == null) {
                LOG.error("responderManager in servlet is not configured");
                return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
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

            if (caName == null || responder == null || !responder.isInService()) {
                String auditMessage;
                if (caName == null) {
                    auditMessage = "no CA is specified";
                } else if (responder == null) {
                    auditMessage = "unknown CA '" + caName + "'";
                } else {
                    auditMessage = "CA '" + caName + "' is out of service";
                }
                LOG.warn(auditMessage);

                return createErrorResponse(version, HttpResponseStatus.NOT_FOUND);
            }

            HealthCheckResult healthResult = responder.healthCheck();
            HttpResponseStatus status = healthResult.isHealthy()
                    ? HttpResponseStatus.OK
                    : HttpResponseStatus.INTERNAL_SERVER_ERROR;
            byte[] respBytes = healthResult.toJsonMessage(true).getBytes();
            return createResponse(version, status, HealthCheckServlet.CT_RESPONSE, respBytes);
        } catch (Throwable th) {
            if (th instanceof EOFException) {
                LogUtil.warn(LOG, th, "connection reset by peer");
            } else {
                LOG.error("Throwable thrown, this should not happen!", th);
            }
            return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
        }
    } // method service0

    public void setResponderManager(final CmpResponderManager responderManager) {
        this.responderManager = ParamUtil.requireNonNull("responderManager", responderManager);
    }

}
