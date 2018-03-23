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

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSession;

import org.xipki.ca.server.api.HttpRequestMetadataRetriever;
import org.xipki.http.servlet.ClientCertCache;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;

import io.netty.handler.codec.http.FullHttpRequest;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

class HttpRequestMetadataRetrieverImpl implements HttpRequestMetadataRetriever {

  private FullHttpRequest request;
  private ServletURI servletUri;
  private SSLSession sslSession;
  private SslReverseProxyMode sslReverseProxyMode;

  public HttpRequestMetadataRetrieverImpl(FullHttpRequest request, ServletURI servletUri,
      SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) {
    this.request = request;
    this.servletUri = servletUri;
    this.sslSession = sslSession;
    this.sslReverseProxyMode = sslReverseProxyMode;
  }

  @Override
  public String getHeader(String headerName) {
    return request.headers().get(headerName);
  }

  @Override
  public String getParameter(String paramName) {
    return servletUri.getParameter(paramName);
  }

  @Override
  public X509Certificate getTlsClientCert() throws IOException {
    return ClientCertCache.getTlsClientCert(request, sslSession, sslReverseProxyMode);
  }

}
