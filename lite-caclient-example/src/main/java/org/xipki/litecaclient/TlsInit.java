/*
 *
 * Copyright (c) 2017 Lijun Liao
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

package org.xipki.litecaclient;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 */

public class TlsInit {

    private static final Logger LOG = LoggerFactory.getLogger(SdkHostnameVerifier.class);

    private static HostnameVerifier oldHostnameVerifier;

    private static final class InternX509TrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1)
                throws CertificateException {
            // TODO: implement me
        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1)
                throws CertificateException {
            // TODO: implement me
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            // TODO: implement me
            return new X509Certificate[0];
        }

    }

    private static class SdkHostnameVerifier implements HostnameVerifier {

        private static SdkHostnameVerifier INSTANCE = new SdkHostnameVerifier();

        /**
         * Verify that the host name is an acceptable match with the server's authentication scheme.
         *
         * @param hostname the host name
         * @param session SSLSession used on the connection to host
         * @return true if the host name is acceptable
         */
        @Override
        public boolean verify(final String hostname, final SSLSession session) {
            // TODO: implement the verification
            return true;
        }

    }

    public static void init() throws GeneralSecurityException {
        System.err.println("***** ONLY FOR TEST, DO NOT USE IT IN PRODUCTION ENVIRONMENT ******");
        TrustManager[] trustManagers = new TrustManager[]{new InternX509TrustManager()};
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustManagers, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        oldHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        LOG.info("Register me as DefaultHostnameVerifier, and backup the old one {}",
                oldHostnameVerifier);
        HttpsURLConnection.setDefaultHostnameVerifier(SdkHostnameVerifier.INSTANCE);
    }

    public static void shutdown() {
        if (HttpsURLConnection.getDefaultHostnameVerifier() == SdkHostnameVerifier.INSTANCE) {
            LOG.info("Unregister me as DefaultHostnameVerifier, and reuse the old one {}",
                    oldHostnameVerifier);
            HttpsURLConnection.setDefaultHostnameVerifier(oldHostnameVerifier);
        }
    }

}
