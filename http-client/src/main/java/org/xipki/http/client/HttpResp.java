package org.xipki.http.client;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class HttpResp {
  
  private int status;
  
  private String statusReasonPhrase;
  
  private Map<String, String> headers;
  
  private byte[] body;

  HttpResp(int status, String statusReasonPhrase, Map<String, String> headers, byte[] body) {
    this.status = status;
    this.statusReasonPhrase = statusReasonPhrase;
    if (headers == null) {
      this.headers = Collections.emptyMap();
    } else {
      this.headers = headers;
    }
    this.body = body;
  }

  public int getStatusCode() {
    return status;
  }

  public String getStatusReasonPhrase() {
    return statusReasonPhrase;
  }

  public Set<String> getHeaderNames() {
    return Collections.unmodifiableSet(headers.keySet());
  }
  
  public String getHeader(String name) {
    return headers.get(name);
  }

  public byte[] getBody() {
    return body;
  }
  
}
