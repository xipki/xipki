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

package org.xipki.p11proxy.server;

import static io.netty.handler.codec.http.HttpResponseStatus.METHOD_NOT_ALLOWED;

import java.io.EOFException;

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.util.LogUtil;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * TODO.
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
      if (!REQUEST_MIMETYPE.equalsIgnoreCase(request.headers().get("Content-Type"))) {
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
  } // method service

  public void setLocalP11CryptServicePool(LocalP11CryptServicePool localP11CryptServicePool) {
    this.localP11CryptServicePool = localP11CryptServicePool;
  }

}
