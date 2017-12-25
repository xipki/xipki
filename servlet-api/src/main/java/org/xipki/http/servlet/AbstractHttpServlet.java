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
 * @since 2.2.0
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
