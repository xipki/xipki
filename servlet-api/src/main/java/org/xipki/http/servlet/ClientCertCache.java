/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.http.servlet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

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

    public static X509Certificate getTlsClientCert(
            final HttpRequest request, final SSLSession session, final SslReverseProxyMode mode)
            throws IOException {
        if (mode == SslReverseProxyMode.NONE || mode == null) {
            if (session == null) {
                return null;
            }

            Certificate[] certs = session.getPeerCertificates();
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
