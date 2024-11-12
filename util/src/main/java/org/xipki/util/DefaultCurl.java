// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.SslConf;
import org.xipki.util.http.SslContextConf;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * An implementation of {@link Curl}.
 *
 * @author Lijun Liao (xipki)
 */

public class DefaultCurl implements Curl {

  private static final class HostConf extends ValidableConf {
    private List<String> urlPattern;
    private SslConf sslContext;

    public void setUrlPattern(List<String> urlPattern) {
      this.urlPattern = urlPattern;
    }

    public void setSslContext(SslConf sslContext) {
      this.sslContext = sslContext;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(urlPattern, "urlPattern");
      notNull(sslContext, "sslContext");
    }
  }

  private static final class CurlConf extends ValidableConf {
    private List<HostConf> hostConfs;

    public void setHostConfs(List<HostConf> hostConfs) {
      this.hostConfs = hostConfs;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (hostConfs == null) {
        return;
      }

      Set<String> urlPatterns = new HashSet<>();
      for (HostConf m : hostConfs) {
        for (String p : m.urlPattern) {
          if (urlPatterns.contains(p)) {
            throw new InvalidConfException("duplicated urlPattern " + p);
          }
          urlPatterns.add(p);
        }
        m.validate();
      }
    }
  }

  private static final class UrlPattern {

    private final String host;

    private final Integer port;

    private final String path;

    private final String toString;

    public UrlPattern(String pattern) {
      if (pattern.startsWith("https://")) {
        pattern = pattern.substring("https://".length());
      }

      int index = pattern.indexOf('/');
      path = pattern.substring(index);
      String token0 = pattern.substring(0, index);
      index = token0.indexOf(':');

      String host0;
      String port0;
      if (index == -1) {
        host0 = token0;
        port0 = "";
      } else {
        host0 = token0.substring(0, index);
        port0 = token0.substring(index + 1);
      }

      this.host = StringUtil.isBlank(host0) ? "*" : host0;
      if (StringUtil.isBlank(port0)) {
        this.port = 443;
        port0 = "443";
      } else if ("*".equals(port0)) {
        this.port = null;
      } else {
        this.port = Integer.parseInt(port0);
      }
      toString = host + ":" + port0 + path;
    }

    public boolean match(URL url) {
      if (!"*".equals(host)) {
        if (!url.getHost().contains(host)) {
          return false;
        }
      }

      if (port != null) {
        int tPort = url.getPort();
        if (tPort == -1) {
          tPort = 443;
        }
        if (port != tPort) {
          return false;
        }
      }

      if (!"/*".equals(path)) {
        String tPath = url.getPath();
        return tPath != null && tPath.startsWith(path);
      }

      return true;
    }

    @Override
    public int hashCode() {
      return toString.hashCode();
    }

    @Override
    public boolean equals(Object other) {
      if (other instanceof UrlPattern) {
        return toString.equals(((UrlPattern) other).toString);
      }
      return false;
    }

    @Override
    public String toString() {
      return toString;
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(DefaultCurl.class);

  private boolean useSslConf = true;

  private String confFile;

  private SslContextConf sslContextConf;

  private Map<UrlPattern, SslContextConf> sslContextConfs = new HashMap<>();

  private UrlPattern[] urlPatterns;

  private boolean initialized;

  public DefaultCurl() {
  }

  public void setUseSslConf(boolean useSslConf) {
    this.useSslConf = useSslConf;
  }

  public void setConfFile(String confFile) {
    this.confFile = confFile;
  }

  public void setSslContextConf(SslContextConf sslContextConf) {
    this.sslContextConf = sslContextConf;
  }

  private synchronized void initIfNotDone() throws ObjectCreationException {
    if (initialized) {
      return;
    }

    try {
      if (useSslConf) {
        if (sslContextConf != null) {
          UrlPattern urlPattern = new UrlPattern("*:*/*");
          try {
            sslContextConf.init();
            sslContextConfs.put(urlPattern, sslContextConf);
            LOG.info("initialized SslContextConf for UrlPattern {}", urlPattern);
          } catch (ObjectCreationException ex) {
            LogUtil.error(LOG, ex, "error initializing sslContextConf");
          }
        } else if (confFile != null) {
          CurlConf conf = JSON.parseConf(Path.of(confFile), CurlConf.class);
          conf.validate();

          for (HostConf m : conf.hostConfs) {
            SslContextConf sslContextConf = SslContextConf.ofSslConf(m.sslContext);

            try {
              sslContextConf.init();
              for (String p : m.urlPattern) {
                sslContextConfs.put(new UrlPattern(p), sslContextConf);
              }
              LOG.info("initialized SslContextConf for UrlPattern {}", m.urlPattern);
            } catch (ObjectCreationException ex) {
              LogUtil.error(LOG, ex, "error initializing SslContextConf for URL pattern " + m.urlPattern);
            }
          }
        } else {
          LOG.info("neither confFile nor sslContextConf is configured, skipping.");
        }

        List<UrlPattern> patterns = new ArrayList<>(sslContextConfs.keySet());
        this.urlPatterns = patterns.toArray(new UrlPattern[0]);
      }
    } catch (InvalidConfException | IOException ex) {
      LogUtil.error(LOG, ex, "error initializing DefaultCurl");
      throw new ObjectCreationException("error initializing DefaultCurl: " + ex.getMessage());
    } finally {
      initialized = true;
    }
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

  /**
   * The specified respContentStream remains open after this method returns.
   */
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
    if (useSslConf && urlPatterns != null && urlPatterns.length > 0 && httpConn instanceof HttpsURLConnection) {
      SslContextConf sslContextConf = null;
      for (UrlPattern m : urlPatterns) {
        if (m.match(newUrl)) {
          sslContextConf = sslContextConfs.get(m);
          break;
        }
      }

      if (sslContextConf != null) {
        HttpsURLConnection httpsConn = ((HttpsURLConnection) httpConn);
        SSLSocketFactory factory = sslContextConf.getSslSocketFactory();
        if (factory != null) {
          httpsConn.setSSLSocketFactory(factory);
        }

        HostnameVerifier verifier = sslContextConf.getHostnameVerifier();
        if (verifier != null) {
          httpsConn.setHostnameVerifier(verifier);
        }
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

      CurlResult result = new CurlResult(respCode);
      result.setContentType(httpConn.getHeaderField("Content-Type"));

      if (inputStream != null) {
        if (respContentStream == null) {
          result.setContent(IoUtil.readAllBytesAndClose(inputStream));
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
        result.setErrorContent(IoUtil.readAllBytesAndClose(errorStream));
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
