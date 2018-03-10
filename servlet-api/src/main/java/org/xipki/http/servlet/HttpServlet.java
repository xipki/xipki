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

import javax.net.ssl.SSLSession;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public interface HttpServlet {

  boolean needsTlsSessionInfo();

  /**
   * TODO.
   * @param request
   *          The request. Must not be {@code null}.
.     * @param servletUri
   *          The servlet URI (URI part after the servlet alias). Must not be {@code null}.
   * @param sslSession
   *          SSLSession associated with this connection. Could be {@code null}.
   * @param sslReverseProxyMode
   *          Mode of the SSL reverse proxy. Must not be {@code null}.
   * @return the HTTP response
   * @throws Exception
   *          If error occurs
   */
  FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
      SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) throws Exception;

}
