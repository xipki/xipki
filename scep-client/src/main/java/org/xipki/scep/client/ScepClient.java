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

import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

/**
 * A concrete SCEP client.
 *
 * @author Lijun Liao
 */

public class ScepClient extends Client {

  private final SSLSocketFactory sslSocketFactory;

  private final HostnameVerifier hostnameVerifier;

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator) {
    this(caId, caCertValidator, null, null);
  }

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator,
      SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    super(caId, caCertValidator);
    this.sslSocketFactory = sslSocketFactory;
    this.hostnameVerifier = hostnameVerifier;
  }

  @Override
  protected ScepHttpResponse httpGet(String url)
      throws ScepClientException {
    Args.notNull(url, "url");
    try {
      HttpURLConnection httpConn = openHttpConn(new URL(url));
      if (httpConn instanceof HttpsURLConnection) {
        if (sslSocketFactory != null) {
          ((HttpsURLConnection) httpConn).setSSLSocketFactory(sslSocketFactory);
        }
        if (hostnameVerifier != null) {
          ((HttpsURLConnection) httpConn).setHostnameVerifier(hostnameVerifier);
        }
      }

      httpConn.setRequestMethod("GET");
      return parseResponse(httpConn);
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
  } // method httpGet

  @Override
  protected ScepHttpResponse httpPost(String url, String requestContentType, byte[] request)
      throws ScepClientException {
    Args.notNull(url, "url");
    try {
      HttpURLConnection httpConn = openHttpConn(new URL(url));
      httpConn.setDoOutput(true);
      httpConn.setUseCaches(false);

      httpConn.setRequestMethod("POST");
      if (request != null) {
        if (requestContentType != null) {
          httpConn.setRequestProperty("Content-Type", requestContentType);
        }

        httpConn.setRequestProperty("Content-Length", Integer.toString(request.length));
        OutputStream outputstream = httpConn.getOutputStream();
        outputstream.write(request);
        outputstream.flush();
      }

      return parseResponse(httpConn);
    } catch (IOException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }
  } // method httpPost

  protected ScepHttpResponse parseResponse(HttpURLConnection conn)
      throws ScepClientException {
    Args.notNull(conn, "conn");

    try {
      InputStream inputstream = conn.getInputStream();
      if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
        inputstream.close();
        throw new ScepClientException("bad response: " + conn.getResponseCode() + "    "
                + conn.getResponseMessage());
      }
      String contentType = conn.getContentType();
      int contentLength = conn.getContentLength();

      ScepHttpResponse resp = new ScepHttpResponse(contentType, contentLength, inputstream);
      String contentEncoding = conn.getContentEncoding();
      if (StringUtil.isNotBlank(contentEncoding)) {
        resp.setContentEncoding(contentEncoding);
      }
      return resp;
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
  } // method parseResponse

  private static HttpURLConnection openHttpConn(URL url)
      throws IOException {
    Args.notNull(url, "url");
    URLConnection conn = url.openConnection();
    if (conn instanceof HttpURLConnection) {
      return (HttpURLConnection) conn;
    }

    throw new IOException(url.toString() + " is not of protocol HTTP: " + url.getProtocol());
  }

}
