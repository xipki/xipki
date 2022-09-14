/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.gateway;

import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class RestResponse {

  private final int statusCode;

  private final String contentType;

  private final Map<String, String> headers;

  private boolean base64;

  private final byte[] body;

  public RestResponse(int statusCode) {
    this(statusCode, null, null, false, null);
  }

  public RestResponse(int statusCode, String contentType, Map<String, String> headers, byte[] body) {
    this(statusCode, contentType, headers, false, body);
  }

  public RestResponse(int statusCode, String contentType, Map<String, String> headers, boolean base64, byte[] body) {
    this.statusCode = statusCode;
    this.base64 = base64;
    this.contentType = contentType;
    this.headers = headers;
    this.body = body;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public String getContentType() {
    return contentType;
  }

  public Map<String, String> getHeaders() {
    return headers;
  }

  public byte[] getBody() {
    return body;
  }

  public void fillResponse(HttpServletResponse resp) throws IOException {
    resp.setStatus(statusCode);
    if (contentType != null) {
      resp.setContentType(contentType);
    }

    if (CollectionUtil.isNotEmpty(headers)) {
      for (Map.Entry<String, String> m : headers.entrySet()) {
        resp.setHeader(m.getKey(), m.getValue());
      }
    }

    if (body == null) {
      resp.setContentLength(0);
    } else {
      byte[] content;
      if (base64) {
        resp.setHeader("Content-Transfer-Encoding", "base64");
        content = Base64.encodeToByte(body, true);
      } else {
        content = body;
      }

      resp.setContentLength(content.length);
      resp.getOutputStream().write(content);
    }
  }

}
