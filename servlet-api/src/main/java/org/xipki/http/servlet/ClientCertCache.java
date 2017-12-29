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

package org.xipki.http.servlet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import io.netty.handler.codec.http.HttpRequest;
import io.netty.util.CharsetUtil;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

class ClientCertCache {
    private static CertificateFactory cf;

    static {
        try {
            cf = CertificateFactory.getInstance("X509");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static final SimpleLruCache<String, X509Certificate> clientCerts =
            new SimpleLruCache<>(100);

    public static X509Certificate getTlsClientCert(HttpRequest request, SSLSession session,
            SslReverseProxyMode mode) throws IOException {
        if (mode == SslReverseProxyMode.NONE || mode == null) {
            if (session == null) {
                return null;
            }

            Certificate[] certs;
            try {
                certs = session.getPeerCertificates();
            } catch (SSLPeerUnverifiedException ex) {
                certs = null;
            }

            Certificate cert = (certs == null || certs.length < 1) ? null : certs[0];
            if (cert != null) {
                return (X509Certificate) cert;
            }
        } else if (mode != SslReverseProxyMode.APACHE) {
            throw new RuntimeException(
                    "Should not reach here, unknown SslReverseProxyMode " + mode);
        }

        // check whether this application is behind a reverse proxy and the TLS client certificate
        // is forwarded. Following headers should be configured to be forwarded:
        // SSL_CLIENT_VERIFY and SSL_CLIENT_CERT.
        // For more details please refer to
        // http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#envvars
        // http://www.zeitoun.net/articles/client-certificate-x509-authentication-behind-reverse-proxy/start
        String clientVerify = request.headers().get("SSL_CLIENT_VERIFY");
        if (clientVerify == null || clientVerify.isEmpty()) {
            return null;
        }

        if (!"SUCCESS".equalsIgnoreCase(clientVerify.trim())) {
            return null;
        }

        String pemClientCert = request.headers().get("SSL_CLIENT_CERT");
        if (pemClientCert == null || pemClientCert.isEmpty()) {
            return null;
        }

        X509Certificate clientCert = clientCerts.get(pemClientCert);
        if (clientCert != null) {
            return clientCert;
        }

        try {
            String b64 = pemClientCert.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "");
            byte[] encoded = Base64.getDecoder().decode(
                                b64.getBytes(CharsetUtil.US_ASCII));
            clientCert = (X509Certificate)
                    cf.generateCertificate(new ByteArrayInputStream(encoded));
        } catch (CertificateException ex) {
            throw new IOException("could not parse Certificate", ex);
        }

        clientCerts.put(pemClientCert, clientCert);
        return clientCert;
    }

}
