/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.server.impl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.xipki.commons.common.LruCache;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class ClientCertCache {

    private static final LruCache<String, X509Certificate> clientCerts = new LruCache<>(50);

    public static X509Certificate getTlsClientCert(final HttpServletRequest request,
            final boolean sslCertInHttpHeader)
    throws IOException {

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(
                "javax.servlet.request.X509Certificate");
        X509Certificate clientCert = (certs == null || certs.length < 1) ? null : certs[0];
        if (clientCert != null) {
            return clientCert;
        }

        if (!sslCertInHttpHeader) {
            return null;
        }

        // check whether this application is behind a reverse proxy and the TLS client certificate
        // is forwarded. Following headers should be configured to be forwarded:
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

        clientCert = clientCerts.get(pemClientCert);
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
    }

}
