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

package org.xipki.ocsp.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.LruCache;
import org.xipki.util.StringUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * For more details please refer to
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

public class TlsHelper {

  private static final Logger LOG = LoggerFactory.getLogger(TlsHelper.class);

  private static final LruCache<String, X509Cert> clientCerts = new LruCache<>(50);

  private static String reverseProxyMode;

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
      X509Certificate[] certs = (X509Certificate[]) request.getAttribute(
          "javax.servlet.request.X509Certificate");
      return (certs == null || certs.length < 1) ? null : new X509Cert(certs[0]);
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

}
