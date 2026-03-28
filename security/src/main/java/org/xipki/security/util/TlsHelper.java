// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.pkix.X509Cert;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.misc.LruCache;
import org.xipki.util.misc.StringUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Tls Helper.
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
 * @author Lijun Liao (xipki)
 */
public class TlsHelper {

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

  private static final Logger LOG = LoggerFactory.getLogger(TlsHelper.class);

  private static final LruCache<String, X509Cert> clientCerts = new LruCache<>(50);
  private static final LruCache<Reference, X509Cert> clientCerts0 = new LruCache<>(50);

  public static void checkReverseProxyMode(String mode) throws InvalidConfException {
    if (mode == null || StringUtil.orEqualsIgnoreCase(mode, "GENERAL", "NGINX", "APACHE")) {
      LOG.info("reverseProxyMode: {}", mode);
    } else {
      String msg = "reverseProxyMode '" + mode + "' in not among [NO,APACHE,NGINX,GENERAL]";
      LOG.error(msg);
      throw new InvalidConfException(msg);
    }
  }

  public static X509Cert getTlsClientCert(XiHttpRequest request, String reverseProxyMode)
      throws IOException {
    if (reverseProxyMode == null || "NO".equalsIgnoreCase(reverseProxyMode)) {
      X509Certificate[] certs = request.getCertificateChain();
      if (certs == null || certs.length < 1) {
        return null;
      }
      X509Certificate cert0 = certs[0];
      Reference ref = new Reference(cert0);

      X509Cert cert = clientCerts0.get(ref);
      if (cert == null) {
        try {
          cert = new X509Cert(Certificate.getInstance(cert0.getEncoded()));
        } catch (CertificateEncodingException e) {
          throw new IOException(e);
        } clientCerts0.put(ref, cert);
      }
      return cert;
    } else if (StringUtil.orEqualsIgnoreCase(reverseProxyMode, "GENERAL", "NGINX", "APACHE")) {
      // check whether this application is behind a reverse proxy and the TLS
      // client certificate is forwarded.
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

      clientCert = parseCertSafe(pemClientCert);
      if (clientCert != null) {
        clientCerts.put(pemClientCert, clientCert);
      }
      return clientCert;
    } else {
      throw new IllegalArgumentException("reverseProxyMode '" +
          reverseProxyMode + "' in not among [NO,APACHE,NGINX,GENERAL]");
    }
  }

  private static X509Cert parseCertSafe(String pemCert) {
    byte[] origBytes = pemCert.getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream bout = new ByteArrayOutputStream(origBytes.length);

    for (int i = 0; i < origBytes.length; i++) {
      int b = origBytes[i] & 0xFF;
      if (b == '\t' || b == '\n' || b == '\r' || b == ' ') {
        continue;
      }

      if (b == '%') {
        if (i + 2 >= origBytes.length) {
          LOG.warn("Malformed SSL_CLIENT_CERT percent-escape");
          return null;
        }
        int hi = Character.digit((char) origBytes[i + 1], 16);
        int lo = Character.digit((char) origBytes[i + 2], 16);
        if (hi < 0 || lo < 0) {
          LOG.warn("Malformed SSL_CLIENT_CERT percent-escape");
          return null;
        }
        b = (hi << 4) | lo;
        i += 2;
      }

      bout.write(b);
    }

    try {
      byte[] derBytes = X509Util.toDerEncoded(bout.toByteArray());
      return new X509Cert(new X509CertificateHolder(derBytes), derBytes);
    } catch (RuntimeException | IOException ex) {
      LOG.warn("Invalid SSL_CLIENT_CERT header");
      return null;
    }
  }

}
