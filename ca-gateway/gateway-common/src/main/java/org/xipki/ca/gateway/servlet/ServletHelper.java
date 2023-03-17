// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;
import org.xipki.util.LruCache;
import org.xipki.util.StringUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * TLS helper.
 *
 * <p>For more details please refer to
 * http://httpd.apache.org/docs/2.2/mod/mod_ssl.html
 * http://www.zeitoun.net/articles/client-certificate-x509-authentication-behind-reverse-proxy/start
 *
 * <p>Please forward at least the following headers:
 * <ul>
 *   <li>SSL_CLIENT_VERIFY</li>
 *   <li>SSL_CLIENT_CERT</li>
 * </ul>
 * @author Lijun Liao
 * @since 2.1.0
 */

public class ServletHelper {

  private static class Reference {
    private final Object obj;

    Reference(Object obj) {
      this.obj = obj;
    }

    public int hashCode() {
      return obj.hashCode();
    }

    public boolean equals(Object another) {
      if (another instanceof Reference) {
        return obj == ((Reference) another).obj;
      }
      return false;
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(ServletHelper.class);

  private static final LruCache<String, X509Cert> clientCerts = new LruCache<>(50);
  private static final LruCache<Reference, X509Cert> clientCerts0 = new LruCache<>(50);

  private static final String reverseProxyMode;

  static {
    String propName = "org.xipki.reverseproxy.mode";
    String mode = System.getProperty(propName);
    if (mode != null && !mode.trim().isEmpty()) {
      mode = mode.trim().toUpperCase();
    }

    if (mode == null || "NO".equals(mode)) {
      reverseProxyMode = null;
    } else if ("APACHE".equals(mode)) {
      reverseProxyMode = "APACHE";
    } else {
      LOG.error("invalid value of property {}: {} is not one of [NO, APACHE]", propName, mode);
      reverseProxyMode = null;
    }

    LOG.info("set reverseProxyMode to {}", reverseProxyMode);
  } // method static

  public static X509Cert getTlsClientCert(HttpServletRequest request)
      throws IOException {
    if (reverseProxyMode == null) {
      X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
      if (certs == null || certs.length < 1) {
        return null;
      }
      X509Certificate cert0 = certs[0];
      Reference ref = new Reference(cert0);

      X509Cert cert = clientCerts0.get(ref);
      if (cert == null) {
        cert = new X509Cert(cert0);
        clientCerts0.put(ref, cert);
      }
      return cert;
    } else if ("APACHE".equals(reverseProxyMode)) {
      // check whether this application is behind a reverse proxy and the TLS client
      // certificate is forwarded.
      String clientVerify = request.getHeader("SSL_CLIENT_VERIFY");
      LOG.debug("SSL_CLIENT_VERIFY: '{}'", clientVerify);

      if (StringUtil.isBlank(clientVerify)) {
        return null;
      }

      if (!"SUCCESS".equalsIgnoreCase(clientVerify.trim())) {
        return null;
      }

      String pemClientCert = request.getHeader("SSL_CLIENT_CERT");
      if (pemClientCert == null || pemClientCert.length() < 100) {
        LOG.error("SSL_CLIENT_CERT: '{}'", pemClientCert);
        // no certificate available
        return null;
      }

      X509Cert clientCert = clientCerts.get(pemClientCert);
      if (clientCert != null) {
        return clientCert;
      }

      try {
        clientCert = X509Util.parseCert(StringUtil.toUtf8Bytes(pemClientCert));
      } catch (CertificateException ex) {
        LOG.error("SSL_CLIENT_CERT: '{}'", pemClientCert);
        throw new IOException("could not parse Certificate", ex);
      }

      clientCerts.put(pemClientCert, clientCert);
      return clientCert;
    } else {
      throw new IllegalStateException("unknown reverseProxyMode " + reverseProxyMode);
    }

  } // method getTlsClientCert

  public static void logReqResp(
      String prefix, Logger log, boolean logReqResp, boolean viaPost,
      HttpServletRequest req, byte[] requestBytes, byte[] respBody) {
    if (logReqResp && log.isDebugEnabled()) {
      String requestURI = req.getRequestURI();

      if (viaPost) {
        log.debug("{} HTTP POST path: {}\nRequest:\n{}\nResponse:\n{}",
            prefix, requestURI, LogUtil.base64Encode(requestBytes), LogUtil.base64Encode(respBody));
      } else {
        log.debug("{} HTTP GET path: {}\nResponse:\n{}", prefix, requestURI, LogUtil.base64Encode(respBody));
      }
    }
  }

}
