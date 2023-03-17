// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

import org.xipki.util.Args;
import org.xipki.util.Base64;
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
 * @author Lijun Liao (xipki)
 */

public class XiHttpClient {

  private final SSLSocketFactory sslSocketFactory;

  private final HostnameVerifier hostnameVerifier;

  public XiHttpClient() {
    this.sslSocketFactory = null;
    this.hostnameVerifier = null;
  }

  public XiHttpClient(SslContextConf sslContextConf) throws ObjectCreationException {
    this.sslSocketFactory = sslContextConf.getSslSocketFactory();
    this.hostnameVerifier = sslContextConf.buildHostnameVerifier();
  }

  public XiHttpClient(SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    this.sslSocketFactory = sslSocketFactory;
    this.hostnameVerifier = hostnameVerifier;
  }

  public HttpRespContent httpGet(String url) throws IOException {
    Args.notNull(url, "url");
    try {
      HttpURLConnection httpConn = openHttpConn(new URL(url));
      httpConn.setRequestMethod("GET");
      return parseResponse(httpConn);
    } catch (XiHttpClientException ex) {
      throw new IOException(ex);
    }
  } // method httpGet

  public HttpRespContent httpPost(
      String url, String requestContentType, byte[] request, String expectedRespContentType)
      throws IOException {
    HttpRespContent resp = httpPost(url, requestContentType, request);

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

    return resp;
  }

  public HttpRespContent httpPost(String url, String requestContentType, byte[] request)
      throws IOException {
    Args.notNull(url, "url");
    try {
      HttpURLConnection httpConn = openHttpConn(new URL(url));
      httpConn.setRequestMethod("POST");
      httpConn.setDoOutput(true);
      httpConn.setUseCaches(false);

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

  private HttpRespContent parseResponse(HttpURLConnection conn) throws XiHttpClientException {
    Args.notNull(conn, "conn");

    try {
      int respCode = conn.getResponseCode();
      InputStream inputstream = respCode == HttpURLConnection.HTTP_OK ? conn.getInputStream() : conn.getErrorStream();
      byte[] content = inputstream == null ? new byte[0] : IoUtil.read(inputstream);
      if (content.length > 0) {
        String encoding = conn.getHeaderField("content-transfer-encoding");
        if (encoding != null && "base64".equalsIgnoreCase(encoding.trim())) {
          content = Base64.decode(content);
        }
      }

      return respCode == HttpURLConnection.HTTP_OK ? HttpRespContent.ofOk(conn.getContentType(), content)
          : HttpRespContent.ofError(respCode, conn.getContentType(), content);
    } catch (IOException ex) {
      throw new XiHttpClientException(ex);
    }
  } // method parseResponse

  private HttpURLConnection openHttpConn(URL url) throws IOException {
    Args.notNull(url, "url");
    URLConnection conn = url.openConnection();
    if (!(conn instanceof HttpURLConnection)) {
      throw new IOException(url + " is not of protocol HTTP: " + url.getProtocol());
    }

    if (conn instanceof HttpsURLConnection) {
      if (sslSocketFactory != null) {
        ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
      }
      if (hostnameVerifier != null) {
        ((HttpsURLConnection) conn).setHostnameVerifier(hostnameVerifier);
      }
    }

    return (HttpURLConnection) conn;
  }

}
