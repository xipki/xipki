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

package org.xipki.ca.server.servlet;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.LruCache;
import org.xipki.common.util.StringUtil;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

public class ClientCertCache {

  private static final Logger LOG = LoggerFactory.getLogger(ClientCertCache.class);

  private static final LruCache<String, X509Certificate> clientCerts = new LruCache<>(50);

  private static String reverseProxyMode = null;

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
      LOG.error("invalid value of property {}: {} is not one of [NO, APACHE]",
          propName, mode);
      reverseProxyMode = null;
    }

    LOG.info("set reverseProxyMode to {}", reverseProxyMode);
  }

  public static X509Certificate getTlsClientCert(final HttpServletRequest request)
      throws IOException {
    if (reverseProxyMode == null) {
      X509Certificate[] certs = (X509Certificate[]) request.getAttribute(
          "javax.servlet.request.X509Certificate");
      return (certs == null || certs.length < 1) ? null : certs[0];
    } else if ("APACHE".equals(reverseProxyMode)) {
      // check whether this application is behind a reverse proxy and the TLS client
      // certificate is forwarded. Following headers should be configured to be forwarded:
      // SSL_CLIENT_VERIFY and SSL_CLIENT_CERT.
      // For more details please refer to
      // http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#envvars
      // http://www.zeitoun.net/articles/client-certificate-x509-authentication-behind-reverse-proxy/start
      String clientVerify = request.getHeader("SSL_CLIENT_VERIFY");
      if (StringUtil.isBlank(clientVerify)) {
        return null;
      }

      if ("SUCCESS".equalsIgnoreCase(clientVerify.trim())) {
        return null;
      }

      String pemClientCert = request.getHeader("SSL_CLIENT_CERT");
      if (StringUtil.isBlank(pemClientCert)) {
        return null;
      }

      X509Certificate clientCert = clientCerts.get(pemClientCert);
      if (clientCert != null) {
        return clientCert;
      }

      try {
        clientCert = X509Util.parsePemEncodedCert(pemClientCert);
      } catch (CertificateException ex) {
        throw new IOException("could not parse Certificate", ex);
      }

      clientCerts.put(pemClientCert, clientCert);
      return clientCert;
    } else {
      throw new RuntimeException("unknown reverseProxyMode " + reverseProxyMode);
    }

  }

}
