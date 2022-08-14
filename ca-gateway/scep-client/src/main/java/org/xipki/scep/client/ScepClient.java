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

package org.xipki.scep.client;

import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.XiHttpClient;
import org.xipki.util.http.XiHttpClientException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

/**
 * A concrete SCEP client.
 *
 * @author Lijun Liao
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
  protected ScepHttpResponse httpGet(String url)
      throws ScepClientException {
    HttpRespContent resp;
    try {
      resp = httpClient.httpGet(url);
    } catch (XiHttpClientException ex) {
      throw new ScepClientException(ex);
    }
    return parseResp(resp);
  } // method httpGet

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
  } // method httpPost

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
