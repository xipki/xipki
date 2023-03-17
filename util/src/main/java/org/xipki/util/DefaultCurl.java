// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.SslContextConf;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * An implementation of {@link Curl}.
 *
 * @author Lijun Liao (xipki)
 */

public class DefaultCurl implements Curl {

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private final SslContextConf sslContextConf;

  private boolean initialized;

  private ObjectCreationException initException;

  public DefaultCurl(SslContextConf sslContextConf) {
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
        initException = new ObjectCreationException("could not initialize DefaultCurl: " + ex.getMessage(), ex);
        throw initException;
      }
    }

    initialized = true;
  }

  private static void println(String text) {
    System.out.println(text);
  }

  @Override
  public CurlResult curlGet(String url, boolean verbose, Map<String, String> headers, String userPassword)
      throws Exception {
    checkUserPassword(userPassword);

    return curlGet(url, null, verbose, headers, userPassword);
  }

  @Override
  public CurlResult curlGet(
      String url, OutputStream respContentStream, boolean verbose, Map<String, String> headers, String userPassword)
      throws Exception {
    return curl(false, url, respContentStream, verbose, headers, userPassword, null);
  }

  @Override
  public CurlResult curlPost(
      String url, boolean verbose, Map<String, String> headers, String userPassword, byte[] content)
      throws Exception {
    return curlPost(url, null, verbose, headers, userPassword, content);
  }

  @Override
  public CurlResult curlPost(
      String url, OutputStream respContentStream, boolean verbose,
      Map<String, String> headers, String userPassword, byte[] content)
      throws Exception {
    return curl(true, url, respContentStream, verbose, headers, userPassword, content);
  }

  private CurlResult curl(
      boolean post, String url, OutputStream respContentStream, boolean verbose,
      Map<String, String> headers, String userPassword, byte[] content)
      throws Exception {
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
        for(Entry<String, String> entry : headers.entrySet()) {
          String value = entry.getValue();
          httpConn.setRequestProperty(entry.getKey(), value);
        }
      }

      if (userPassword != null) {
        httpConn.setRequestProperty("Authorization",
            "Basic " + Base64.encodeToString(StringUtil.toUtf8Bytes(userPassword)));
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
        for (Entry<String, List<String>> entry : properties.entrySet()) {
          for (String value : entry.getValue()) {
            println("  " + entry.getKey() + ": " + value);
          }
        }
      }

      // read the response
      int respCode = httpConn.getResponseCode();
      if (verbose) {
        println("=====response=====");
        println("  response code: " + respCode + " " + httpConn.getResponseMessage());
        properties = httpConn.getHeaderFields();
        for (Entry<String, List<String>> entry : properties.entrySet()) {
          String key = entry.getKey();
          if (key == null) {
            continue;
          }
          List<String> values = entry.getValue();
          for (String value : values) {
            println("  " + key + ": " + value);
          }
        }
        println("=====response content=====");
      } else {
        if (respCode != HttpURLConnection.HTTP_OK) {
          println("ERROR: bad response: " + httpConn.getResponseCode() + "    " + httpConn.getResponseMessage());
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
        if (respContentStream == null) {
          result.setContent(IoUtil.read(inputStream));
        } else {
          byte[] buffer = new byte[8192];
          int read;
          int contentLength = 0;
          while ((read = inputStream.read(buffer)) != -1) {
            contentLength += read;
            respContentStream.write(buffer, 0, read);
          }
          result.setContentLength(contentLength);
        }
      } else if (errorStream != null) {
        result.setErrorContent(IoUtil.read(errorStream));
      }

      return result;
    } finally {
      httpConn.disconnect();
    }
  } // method curl

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
