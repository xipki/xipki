/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.xipki.util.http.SslContextConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class DefaultCurl implements Curl {

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private SslContextConf sslContextConf;

  private boolean initialized;

  private ObjectCreationException initException;

  public void setSslContextConf(SslContextConf sslContextConf) {
    this.sslContextConf = sslContextConf;
  }

  private synchronized void initIfNotDone() throws ObjectCreationException {
    if (initException != null) {
      throw initException;
    }

    if (initialized) {
      return;
    }

    if (sslContextConf != null && sslContextConf.isUseSslConf()) {
      try {
        sslSocketFactory = sslContextConf.getSslSocketFactory();
        hostnameVerifier = sslContextConf.buildHostnameVerifier();
      } catch (ObjectCreationException ex) {
        initException = new ObjectCreationException(
            "could not initialize DefaultCurl: " + ex.getMessage(), ex);
        throw initException;
      }
    }

    initialized = true;
  }

  private static void println(String text) {
    System.out.println(text);
  }

  @Override
  public CurlResult curlGet(String url, boolean verbose, Map<String, String> headers,
      String userPassword) throws Exception {
    checkUserPassword(userPassword);

    return curl(false, url, verbose, headers, userPassword, null);
  }

  @Override
  public CurlResult curlPost(String url, boolean verbose, Map<String, String> headers,
      String userPassword, byte[] content) throws Exception {
    return curl(true, url, verbose, headers, userPassword, content);
  }

  private CurlResult curl(boolean post, String url, boolean verbose, Map<String, String> headers,
      String userPassword, byte[] content) throws Exception {
    if (!post && content != null) {
      throw new IllegalArgumentException("method GET cannot be used to transfer non-empty content");
    }

    checkUserPassword(userPassword);

    initIfNotDone();

    URL newUrl = new URL(url);
    HttpURLConnection httpConn = IoUtil.openHttpConn(newUrl);
    if (httpConn instanceof HttpsURLConnection) {
      if (sslSocketFactory != null) {
        ((HttpsURLConnection) httpConn).setSSLSocketFactory(sslSocketFactory);
      }
      if (hostnameVerifier != null) {
        ((HttpsURLConnection) httpConn).setHostnameVerifier(hostnameVerifier);
      }
    }

    try {
      httpConn.setRequestMethod(post ? "POST" : "GET");
      httpConn.setUseCaches(false);

      if (headers != null) {
        for (String headerName : headers.keySet()) {
          String value = headers.get(headerName);
          httpConn.setRequestProperty(headerName, value);
        }
      }

      if (userPassword != null) {
        httpConn.setRequestProperty("Authorization",
            "Basic " + Base64.encodeToString(userPassword.getBytes()));
      }

      Map<String, List<String>> properties;

      if (content == null) {
        properties = httpConn.getRequestProperties();
      } else {
        httpConn.setDoOutput(true);
        httpConn.setRequestProperty("Content-Length", Integer.toString(content.length));
        properties = httpConn.getRequestProperties();

        OutputStream outputstream = httpConn.getOutputStream();
        outputstream.write(content);
        outputstream.flush();
      }

      // show the request headers
      if (verbose) {
        println("=====request=====");
        println("  HTTP method: " + httpConn.getRequestMethod());
        for (String key : properties.keySet()) {
          List<String> values = properties.get(key);
          for (String value : values) {
            println("  " + key + ": " + value);
          }
        }
      }

      // read the response
      int respCode = httpConn.getResponseCode();
      if (verbose) {
        println("=====response=====");
        println("  response code: " + respCode + " " + httpConn.getResponseMessage());
        properties = httpConn.getHeaderFields();
        for (String key : properties.keySet()) {
          if (key == null) {
            continue;
          }
          List<String> values = properties.get(key);
          for (String value : values) {
            println("  " + key + ": " + value);
          }
        }
        println("=====response content=====");
      } else {
        if (respCode != HttpURLConnection.HTTP_OK) {
          println("ERROR: bad response: " + httpConn.getResponseCode() + "    "
              + httpConn.getResponseMessage());
        }
      }

      InputStream inputStream = null;
      InputStream errorStream = null;

      try {
        inputStream = httpConn.getInputStream();
      } catch (IOException ex) {
        errorStream = httpConn.getErrorStream();
      }

      CurlResult result = new CurlResult();
      result.setContentType(httpConn.getHeaderField("Content-Type"));
      if (inputStream != null) {
        result.setContent(IoUtil.read(inputStream));
      } else if (errorStream != null) {
        result.setErrorContent(IoUtil.read(errorStream));
      }

      return result;
    } finally {
      httpConn.disconnect();
    }
  }

  private void checkUserPassword(String userPassword) {
    if (userPassword == null) {
      return;
    }

    int idx = userPassword.indexOf(':');
    if (idx == -1 || idx == userPassword.length() - 1) {
      throw new IllegalArgumentException("invalid userPassword");
    }
  }

}
