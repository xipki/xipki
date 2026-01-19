// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.util.extra.http.Curl;
import org.xipki.util.extra.http.DefaultCurl;
import org.xipki.util.extra.http.HttpStatusCode;

import java.util.HashMap;
import java.util.Map;

/**
 * A concrete SCEP client.
 *
 * @author Lijun Liao (xipki)
 */

public class ScepClient extends Client {

  private final Curl curl;

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator) {
    this(caId, caCertValidator, null);
  }

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator,
                    Curl curl) {
    super(caId, caCertValidator);
    this.curl = curl == null ? new DefaultCurl() : curl;
  }

  @Override
  protected ScepHttpResponse httpGet(String url) throws ScepClientException {
    Curl.CurlResult resp;
    try {
      resp = curl.curlGet(url, false, null, null);
    } catch (Exception ex) {
      throw new ScepClientException(ex);
    }
    return parseResp(resp);
  }

  @Override
  protected ScepHttpResponse httpPost(String url, String requestContentType,
                                      byte[] request)
      throws ScepClientException {
    Curl.CurlResult resp;
    try {
      Map<String, String> headers = null;
      if (requestContentType != null) {
        headers = new HashMap<>();
        headers.put("content-type", requestContentType);
      }

      resp = curl.curlPost(url, false, headers, null, request);
    } catch (Exception ex) {
      throw new ScepClientException(ex);
    }
    return parseResp(resp);
  }

  private static ScepHttpResponse parseResp(Curl.CurlResult resp)
      throws ScepClientException {
    int statusCode = resp.getStatusCode();
    if (statusCode != HttpStatusCode.SC_OK) {
      String msg = "server returned status code " + statusCode;
      byte[] errorContent = resp.getErrorContent();
      if (errorContent != null && errorContent.length != 0) {
        msg += ", message: " + new String(errorContent);
      }
      throw new ScepClientException(msg);
    }

    return new ScepHttpResponse(resp.getContentType(), resp.getContent());
  }

}
