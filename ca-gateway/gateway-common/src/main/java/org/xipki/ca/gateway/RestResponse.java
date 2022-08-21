package org.xipki.ca.gateway;

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

  private final byte[] body;

  public RestResponse(int statusCode) {
    this(statusCode, null, null, null);
  }

  public RestResponse(int statusCode, String contentType, Map<String, String> headers, byte[] body) {
    this.statusCode = statusCode;
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

  public void fillResponse(HttpServletResponse resp)
      throws IOException {
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
      resp.setContentLength(body.length);
      resp.getOutputStream().write(body);
    }
  }

}
