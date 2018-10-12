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

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.api.ResponderManager;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.security.X509Cert;

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

public class HttpCaCertServlet extends AbstractHttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpCaCertServlet.class);

  private static final String CT_RESPONSE = "application/pkix-cert";

  private ResponderManager responderManager;

  public HttpCaCertServlet() {
  }

  @Override
  public boolean needsTlsSessionInfo() {
    return true;
  }

  @Override
  public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
      SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) throws Exception {
    HttpVersion httpVersion = request.protocolVersion();
    HttpMethod method = request.method();
    if (method != HttpMethod.GET && method != HttpMethod.POST) {
      return createErrorResponse(httpVersion, HttpResponseStatus.METHOD_NOT_ALLOWED);
    }

    try {
      if (responderManager == null) {
        String message = "responderManager in servlet not configured";
        LOG.error(message);
        return createErrorResponse(httpVersion, HttpResponseStatus.INTERNAL_SERVER_ERROR);
      }

      String caName = null;
      if (servletUri.getPath().length() > 1) {
        // skip the first char which is always '/'
        String caAlias = servletUri.getPath().substring(1);
        caName = responderManager.getCaNameForAlias(caAlias);
        if (caName == null) {
          caName = caAlias.toLowerCase();
        }
      }

      X509Cert cacert = null;
      if (caName != null) {
        cacert = responderManager.getCaCert(caName);
      }

      if (cacert == null) {
        return createErrorResponse(httpVersion, HttpResponseStatus.NOT_FOUND);
      }

      return createOKResponse(httpVersion, CT_RESPONSE, cacert.getEncodedCert());
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      return createErrorResponse(httpVersion, HttpResponseStatus.INTERNAL_SERVER_ERROR);
    }
  } // method service

  public void setResponderManager(ResponderManager responderManager) {
    this.responderManager = responderManager;
  }

  @Override
  public int getMaxUriSize() {
    return 200;
  }

  @Override
  public int getMaxRequestSize() {
    // empty content is expected
    return 0;
  }

}
