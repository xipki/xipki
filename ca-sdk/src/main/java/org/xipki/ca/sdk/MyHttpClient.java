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

package org.xipki.ca.sdk;

import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;

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
 * The SDK client.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class MyHttpClient {

  private final SSLSocketFactory sslSocketFactory;

  private final HostnameVerifier hostnameVerifier;

  public MyHttpClient(SSLSocketFactory sslSocketFactory,
                      HostnameVerifier hostnameVerifier,
                      X509Cert serverCert) {
    this.sslSocketFactory = sslSocketFactory;
    this.hostnameVerifier = hostnameVerifier;
  }

  protected byte[] httpGet(String url)
      throws SdkClientException {
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
      throw new SdkClientException(ex);
    }
  } // method httpGet

  protected byte[] httpPost(String url, String requestContentType, byte[] request)
      throws SdkClientException {
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
      throw new SdkClientException(ex.getMessage(), ex);
    }
  } // method httpPost

  protected byte[] parseResponse(HttpURLConnection conn)
      throws SdkClientException {
    Args.notNull(conn, "conn");

    try {
      InputStream inputstream = conn.getInputStream();
      if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
        inputstream.close();
        throw new SdkClientException("bad response: " + conn.getResponseCode() + "    "
                + conn.getResponseMessage());
      }

      return IoUtil.read(inputstream);
    } catch (IOException ex) {
      throw new SdkClientException(ex);
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
