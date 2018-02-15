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

package org.xipki.security;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509Cert {

    private final X509Certificate cert;

    private final String subject;

    private final byte[] encodedCert;

    private final byte[] subjectKeyIdentifer;

    private final X500Name subjectAsX500Name;

    private X509CertificateHolder certHolder;

    public X509Cert(X509Certificate cert) {
        this(cert, null);
    }

    public X509Cert(X509Certificate cert, byte[] encodedCert) {
        this.cert = ParamUtil.requireNonNull("cert", cert);

        X500Principal x500Subject = cert.getSubjectX500Principal();
        this.subject = X509Util.getRfc4519Name(x500Subject);
        this.subjectAsX500Name = X500Name.getInstance(x500Subject.getEncoded());
        try {
            this.subjectKeyIdentifer = X509Util.extractSki(cert);
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(String.format(
                    "CertificateEncodingException: %s", ex.getMessage()));
        }

        if (encodedCert != null) {
            this.encodedCert = encodedCert;
        } else {
            try {
                this.encodedCert = cert.getEncoded();
            } catch (CertificateEncodingException ex) {
                throw new RuntimeException(
                        String.format("CertificateEncodingException: %s", ex.getMessage()));
            }
        }
    }

    public X509Certificate cert() {
        return cert;
    }

    public byte[] encodedCert() {
        return encodedCert;
    }

    public String subject() {
        return subject;
    }

    public X500Name subjectAsX500Name() {
        return subjectAsX500Name;
    }

    public byte[] subjectKeyIdentifier() {
        return Arrays.copyOf(subjectKeyIdentifer, subjectKeyIdentifer.length);
    }

    public X509CertificateHolder certHolder() {
        if (certHolder != null) {
            return certHolder;
        }

        synchronized (cert) {
            try {
                certHolder = new X509CertificateHolder(encodedCert);
            } catch (IOException ex) {
                throw new RuntimeException("should not happen, could not decode certificate: "
                        + ex.getMessage());
            }
            return certHolder;
        }
    }

    @Override
    public String toString() {
        return cert.toString();
    }

    @Override
    public int hashCode() {
        return cert.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (!(obj instanceof X509Cert)) {
            return false;
        }

        return Arrays.equals(encodedCert, ((X509Cert) obj).encodedCert);
    }

}
