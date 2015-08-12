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

package org.xipki.scep4j.client;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.xipki.scep4j.crypto.HashAlgoType;

/**
 * @author Lijun Liao
 */

public abstract class FingerprintCertificateValidator
implements CACertValidator
{
    private static final HashAlgoType DEFAULT_HASHALGO = HashAlgoType.SHA256;
    private HashAlgoType hashAlgo;

    public HashAlgoType getHashAlgo()
    {
        return hashAlgo;
    }

    public void setHashAlgo(
            final HashAlgoType hashAlgo)
    {

        this.hashAlgo = hashAlgo;
    }

    @Override
    public boolean isTrusted(
            final X509Certificate cert)
    {
        HashAlgoType algo = hashAlgo == null ? DEFAULT_HASHALGO : hashAlgo;
        byte[] actual;
        try
        {
            actual = algo.digest(cert.getEncoded());
        } catch (CertificateEncodingException e)
        {
            return false;
        }

        return isCertTrusted(algo, actual);
    }

    protected abstract boolean isCertTrusted(
            HashAlgoType hashAlgo,
            byte[] hashValue);
}
