// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.XiHttpClient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

/**
 * A concrete SCEP client.
 *
 * @author Lijun Liao (xipki)
 */

public class ScepClient extends Client {

  private final XiHttpClient httpClient;

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator) {
    this(caId, caCertValidator, null, null);
  }

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator,
                    SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    super(caId, caCertValidator);
    this.httpClient = new XiHttpClient(sslSocketFactory, hostnameVerifier);
  }

  @Override
  protected ScepHttpResponse httpGet(String url) throws ScepClientException {
    HttpRespContent resp;
    try {
      resp = httpClient.httpGet(url);
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
    return parseResp(resp);
  }

  @Override
  protected ScepHttpResponse httpPost(String url, String requestContentType, byte[] request)
      throws ScepClientException {
    HttpRespContent resp;
    try {
      resp = httpClient.httpPost(url, requestContentType, request);
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
    return parseResp(resp);
  }

  private static ScepHttpResponse parseResp(HttpRespContent resp) throws ScepClientException {
    byte[] content = resp.getContent();
    if (!resp.isOK()) {
      String msg = "server returned status code " + resp.getStatusCode();
      if (content != null && content.length != 0) {
        msg += ", message: " + new String(content);
      }
      throw new ScepClientException(msg);
    }

    return new ScepHttpResponse(resp.getContentType(), content);
  }

}
