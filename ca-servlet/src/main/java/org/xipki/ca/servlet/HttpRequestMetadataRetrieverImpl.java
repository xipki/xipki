/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.servlet;

import org.xipki.security.X509Cert;
import org.xipki.security.util.HttpRequestMetadataRetriever;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * HTTP request metadata retriever.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

class HttpRequestMetadataRetrieverImpl implements HttpRequestMetadataRetriever {

  private final HttpServletRequest req;

  HttpRequestMetadataRetrieverImpl(HttpServletRequest req) {
    this.req = req;
  }

  @Override
  public String getHeader(String headerName) {
    return req.getHeader(headerName);
  }

  @Override
  public String getParameter(String paramName) {
    return req.getParameter(paramName);
  }

  @Override
  public X509Cert getTlsClientCert() throws IOException {
    return TlsHelper.getTlsClientCert(req);
  }

}
