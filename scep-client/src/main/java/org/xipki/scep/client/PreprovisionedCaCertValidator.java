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

package org.xipki.scep.client;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.xipki.scep.crypto.ScepHashAlgoType;
import org.xipki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public final class PreprovisionedCaCertValidator implements CaCertValidator {

    private final Set<String> fpOfCerts;

    public PreprovisionedCaCertValidator(final X509Certificate cert) {
        ScepUtil.requireNonNull("cert", cert);
        fpOfCerts = new HashSet<String>(1);
        String hexFp;
        try {
            hexFp = ScepHashAlgoType.SHA256.hexDigest(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            throw new IllegalArgumentException(
                    "at least one of the certificate could not be encoded");
        }
        fpOfCerts.add(hexFp);
    }

    public PreprovisionedCaCertValidator(final Set<X509Certificate> certs) {
        ScepUtil.requireNonNull("certs", certs);
        fpOfCerts = new HashSet<String>(certs.size());
        for (X509Certificate m : certs) {
            String hexFp;
            try {
                hexFp = ScepHashAlgoType.SHA256.hexDigest(m.getEncoded());
            } catch (CertificateEncodingException ex) {
                throw new IllegalArgumentException(
                        "at least one of the certificate could not be encoded");
            }
            fpOfCerts.add(hexFp);
        }
    }

    @Override
    public boolean isTrusted(final X509Certificate cert) {
        ScepUtil.requireNonNull("cert", cert);
        String hextFp;
        try {
            hextFp = ScepHashAlgoType.SHA256.hexDigest(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            return false;
        }
        return fpOfCerts.contains(hextFp);
    }

}
