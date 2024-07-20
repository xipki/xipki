// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class HttpResponse {

  private final int statusCode;

  private final String contentType;

  private final Map<String, List<String>> headers;

  private final boolean base64;

  private final byte[] body;

  public HttpResponse(int statusCode) {
    this(statusCode, null, null, false, null);
  }

  public HttpResponse(int statusCode, String contentType, Map<String, String> headers, byte[] body) {
    this(statusCode, contentType, headers, false, body);
  }

  public HttpResponse(int statusCode, String contentType, Map<String, String> headers, boolean base64, byte[] body) {
    this.statusCode = statusCode;
    this.base64 = base64;
    this.contentType = contentType;
    this.headers = new HashMap<>();
    if (headers != null) {
      for (Map.Entry<String, String> m : headers.entrySet()) {
        this.headers.put(m.getKey(), Collections.singletonList(m.getValue()));
      }
    }
    this.body = body;
  }

  public boolean isBase64() {
    return base64;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public String getContentType() {
    return contentType;
  }

  public Map<String, List<String>> getHeaders() {
    return headers;
  }

  public byte[] getBody() {
    return body;
  }
  public HttpResponse putHeader(String name, String value) {
    List<String> values = headers.computeIfAbsent(name, k -> new ArrayList<>(1));
    values.add(value);
    return this;
  }

  public void fillResponse(XiHttpResponse resp) throws IOException {
    resp.setStatus(statusCode);
    if (contentType != null) {
      resp.setContentType(contentType);
    }

    if (CollectionUtil.isNotEmpty(headers)) {
      for (Map.Entry<String, List<String>> m : headers.entrySet()) {
        for (String value : m.getValue()) {
          resp.addHeader(m.getKey(), value);
        }
      }
    }

    if (body == null || body.length == 0) {
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
