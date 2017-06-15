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

package org.xipki.remotep11.server;

import static io.netty.handler.codec.http.HttpResponseStatus.METHOD_NOT_ALLOWED;

import java.io.EOFException;

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpProxyServlet extends AbstractHttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HttpProxyServlet.class);

    private static final String REQUEST_MIMETYPE = "application/x-xipki-pkcs11";

    private static final String RESPONSE_MIMETYPE = "application/x-xipki-pkcs11";

    private final P11ProxyResponder responder;

    private LocalP11CryptServicePool localP11CryptServicePool;

    public HttpProxyServlet() {
        responder = new P11ProxyResponder();
    }

    @Override
    public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) throws Exception {
        HttpVersion version = request.protocolVersion();
        HttpMethod method = request.method();

        if (method != HttpMethod.POST) {
            return createErrorResponse(version, METHOD_NOT_ALLOWED);
        }

        try {
            if (!REQUEST_MIMETYPE.equalsIgnoreCase(
                    request.headers().get("Content-Type"))) {
                return createErrorResponse(version, HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE);
            }

            if (localP11CryptServicePool == null) {
                LOG.error("localP11CryptService in servlet not configured");
                return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
            }

            byte[] requestBytes = readContent(request);
            byte[] responseBytes = responder.processRequest(localP11CryptServicePool, requestBytes);
            return createOKResponse(version, RESPONSE_MIMETYPE, responseBytes);
        } catch (Throwable th) {
            if (th instanceof EOFException) {
                LogUtil.warn(LOG, th, "connection reset by peer");
            } else {
                LOG.error("Throwable thrown, this should not happen.", th);
            }
            return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
        }
    } // method doPost

    public void setLocalP11CryptServicePool(
            final LocalP11CryptServicePool localP11CryptServicePool) {
        this.localP11CryptServicePool = localP11CryptServicePool;
    }

}
