/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.scep4j.message;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;

import org.xipki.scep4j.crypto.HashAlgoType;
import org.xipki.scep4j.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public class CollectionCertificateValidator
implements CertificateValidator
{
    private final Collection<String> certHashes;

    public CollectionCertificateValidator(
            final Collection<X509Certificate> certs)
    {
        ParamUtil.assertNotEmpty("certs", certs);
        certHashes = new HashSet<String>(certs.size());
        for(X509Certificate cert : certs)
        {
            String hash;
            try
            {
                hash = HashAlgoType.SHA256.hexDigest(cert.getEncoded());
            } catch (CertificateEncodingException e)
            {
                throw new IllegalArgumentException("could not encode certificate: " + e.getMessage(), e);
            }
            certHashes.add(hash);
        }
    }

    public CollectionCertificateValidator(
            final X509Certificate cert)
    {
        ParamUtil.assertNotNull("cert", cert);

        certHashes = new HashSet<String>(1);
        String hash;
        try
        {
            hash = HashAlgoType.SHA256.hexDigest(cert.getEncoded());
        } catch (CertificateEncodingException e)
        {
            throw new IllegalArgumentException("could not encode certificate: " + e.getMessage(), e);
        }
        certHashes.add(hash);
    }

    @Override
    public boolean trustCertificate(
            final X509Certificate signerCert,
            final X509Certificate[] signerCaCerts)
    {
        ParamUtil.assertNotNull("signerCert", signerCert);

        String hash;
        try
        {
            hash = HashAlgoType.SHA256.hexDigest(signerCert.getEncoded());
        } catch (CertificateEncodingException e)
        {
            throw new IllegalArgumentException("could not encode certificate: " + e.getMessage(), e);
        }
        return certHashes.contains(hash);
    }

}
