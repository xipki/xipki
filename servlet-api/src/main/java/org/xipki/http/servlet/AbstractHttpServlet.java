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

package org.xipki.http.servlet;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSession;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * @author Lijun Liao
 * @since 2.2.0O
 */

public abstract class AbstractHttpServlet implements HttpServlet {

    @Override
    public boolean needsTlsSessionInfo() {
        return false;
    }

    protected static byte[] readContent(FullHttpRequest request) {
        ByteBuf buf = request.content();
        if (buf == null) {
            return null;
        }
        byte[] bytes = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), bytes);
        return bytes;
    }

    protected static FullHttpResponse createOKResponse(HttpVersion version,
            String contentType, byte[] content) {
        return createResponse(version, HttpResponseStatus.OK, contentType, content);
    }

    protected static FullHttpResponse createResponse(HttpVersion version,
            HttpResponseStatus status, String contentType, byte[] content) {
        FullHttpResponse resp;
        ByteBuf buf = null;
        int contentLen = (content == null) ? 0 : content.length;

        if (contentLen != 0) {
            buf = Unpooled.wrappedBuffer(content);
            resp = new DefaultFullHttpResponse(version, status, buf);
        } else {
            resp = new DefaultFullHttpResponse(version, status);
        }
        resp.headers().addInt("Content-Length", contentLen);

        if (contentType != null && !contentType.isEmpty()) {
            resp.headers().add("Content-Type", contentType);
        }
        return resp;
    }

    protected static FullHttpResponse createErrorResponse(HttpVersion version,
            HttpResponseStatus status) {
        FullHttpResponse resp = new DefaultFullHttpResponse(version, status);
        resp.headers().addInt("Content-Length", 0);
        return resp;
    }

    protected X509Certificate getClientCert(HttpRequest request, SSLSession sslSession,
            SslReverseProxyMode sslReverseProxyMode)
            throws IOException {
        return ClientCertCache.getTlsClientCert(request, sslSession, sslReverseProxyMode);
    }

}
