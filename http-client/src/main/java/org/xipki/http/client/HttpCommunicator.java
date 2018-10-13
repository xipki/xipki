package org.xipki.http.client;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

public class HttpCommunicator {
  
  private CloseableHttpClient client;
  
  HttpCommunicator(CloseableHttpClient client) {
    this.client = client;
  }

  public HttpResp httpGet(String uri, Map<String, String> headers) throws IOException {
    HttpGet request = new HttpGet(uri);
    if (headers != null) {
      for (String hname : headers.keySet()) {
        request.setHeader(hname, headers.get(hname));
      }
    }

    CloseableHttpResponse resp = client.execute(request);
    return parseResponse(resp);
  }

  public HttpResp httpPost(String uri, Map<String, String> headers, byte[] req)
      throws IOException {
    HttpPost request = new HttpPost(uri);
    if (headers != null) {
      for (String hname : headers.keySet()) {
        request.setHeader(hname, headers.get(hname));
      }
      request.setHeader("Content-Length", Integer.toString(req == null ? 0 : req.length));
    }
    
    if (req != null) {
      request.setEntity(new ByteArrayEntity(req));
    }

    CloseableHttpResponse resp = client.execute(request);
    return parseResponse(resp);
  }

  private HttpResp parseResponse(CloseableHttpResponse resp) throws IOException {
    StatusLine statusLine = resp.getStatusLine();
    Map<String, String> respHeaders = new HashMap<>();
    for (Header header : resp.getAllHeaders()) {
      respHeaders.put(header.getName(), header.getValue());
    }
    
    byte[] body = EntityUtils.toByteArray(resp.getEntity());
    return new HttpResp(statusLine.getStatusCode(), statusLine.getReasonPhrase(),
        respHeaders, body);
  }
}
