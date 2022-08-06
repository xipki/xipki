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

package org.xipki.util.http;

import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.ObjectCreationException;

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
 * The HTTP client.
 *
 * @author Lijun Liao
 */

public class XiHttpClient {

  private final SSLSocketFactory sslSocketFactory;

  private final HostnameVerifier hostnameVerifier;

  public XiHttpClient() {
    this.sslSocketFactory = null;
    this.hostnameVerifier = null;
  }

  public XiHttpClient(SslContextConf sslContextConf)
      throws ObjectCreationException {
    this.sslSocketFactory = sslContextConf.getSslSocketFactory();
    this.hostnameVerifier = sslContextConf.buildHostnameVerifier();
  }

  public XiHttpClient(SSLSocketFactory sslSocketFactory,
                      HostnameVerifier hostnameVerifier) {
    this.sslSocketFactory = sslSocketFactory;
    this.hostnameVerifier = hostnameVerifier;
  }

  public HttpRespContent httpGet(String url)
      throws XiHttpClientException {
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
      throw new XiHttpClientException(ex);
    }
  } // method httpGet


  public byte[] httpPost(String url, String requestContentType, byte[] request,
                         String expectedRespContentType)
      throws IOException {
    HttpRespContent resp = httpPost(url, requestContentType, request);
    byte[] body = resp.getContent();
    if (body == null) {
      return null;
    }

    String responseContentType = resp.getContentType();
    boolean isValidContentType = false;
    if (responseContentType != null) {
      if (responseContentType.equalsIgnoreCase(expectedRespContentType)) {
        isValidContentType = true;
      }
    }

    if (!isValidContentType) {
      throw new IOException("bad response: mime type " + responseContentType + " not supported!");
    }

    return body;
  }

  public HttpRespContent httpPost(String url, String requestContentType, byte[] request)
      throws IOException {
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
    } catch (XiHttpClientException ex) {
      throw new IOException(ex.getMessage(), ex);
    }
  } // method httpPost

  private HttpRespContent parseResponse(HttpURLConnection conn)
      throws XiHttpClientException {
    Args.notNull(conn, "conn");

    try {
      InputStream inputstream = conn.getInputStream();
      if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
        inputstream.close();
        throw new XiHttpClientException("bad response: " + conn.getResponseCode() + "    "
                + conn.getResponseMessage());
      }

      HttpRespContent respContent = new HttpRespContent();
      respContent.setContent(IoUtil.read(inputstream));
      respContent.setContentType(conn.getContentType());
      return respContent;
    } catch (IOException ex) {
      throw new XiHttpClientException(ex);
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
