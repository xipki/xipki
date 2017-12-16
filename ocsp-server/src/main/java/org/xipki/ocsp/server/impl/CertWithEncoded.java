/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ocsp.server.impl;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertWithEncoded {

    private final X509Certificate certificate;

    private final String className;

    private final byte[] encoded;

    public CertWithEncoded(final X509Certificate cert) throws CertificateEncodingException {
        this.certificate = ParamUtil.requireNonNull("cert", cert);
        this.className = cert.getClass().getName();
        this.encoded = cert.getEncoded();
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public boolean equalsCert(final X509Certificate cert) {
        if (cert == null) {
            return false;
        }
        if (certificate == cert) {
            return true;
        }

        if (className.equals(cert.getClass().getName())) {
            return certificate.equals(cert);
        } else if (certificate.equals(cert)) {
            return true;
        } else {
            byte[] encodedCert;
            try {
                encodedCert = cert.getEncoded();
            } catch (CertificateEncodingException ex) {
                return false;
            }
            return Arrays.equals(encoded, encodedCert);
        }
    }

}
