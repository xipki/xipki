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

import java.util.Date;

import javax.net.ssl.SSLSession;

import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.ca.server.api.CmpResponderManager;
import org.xipki.ca.server.api.HttpRequestMetadataRetriever;
import org.xipki.ca.server.api.Rest;
import org.xipki.ca.server.api.RestResponse;
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
 * @since 2.1.0
 */

public class HttpRestServlet extends AbstractHttpServlet {

    private CmpResponderManager responderManager;

    private AuditServiceRegister auditServiceRegister;

    public HttpRestServlet() {
    }

    @Override
    public boolean needsTlsSessionInfo() {
        return true;
    }

    @Override
    public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) {
        HttpVersion version = request.protocolVersion();
        HttpMethod method = request.method();
        if (method != HttpMethod.POST && method != HttpMethod.GET) {
            return createErrorResponse(version, HttpResponseStatus.METHOD_NOT_ALLOWED);
        }

        AuditEvent event = new AuditEvent(new Date());

        try {
            Rest rest = responderManager.getRest();
            HttpRequestMetadataRetriever httpRetriever = new HttpRequestMetadataRetrieverImpl(
                    request, servletUri, sslSession, sslReverseProxyMode);
            byte[] requestBytes = readContent(request);
            RestResponse response = rest.service(servletUri.path(), event, requestBytes, httpRetriever);

            HttpResponseStatus status = HttpResponseStatus.valueOf(response.statusCode());
            FullHttpResponse resp= createResponse(version, status, response.contentType(),
                    response.body());
            for (String headerName : response.headers().keySet()) {
                resp.headers().add(headerName, response.headers().get(headerName));
            }
            return resp;
        } finally {
            event.finish();
            auditServiceRegister.getAuditService().logEvent(event);
        }
    } // method service

    public void setResponderManager(CmpResponderManager responderManager) {
        this.responderManager = responderManager;
    }

    public void setAuditServiceRegister(AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

}
