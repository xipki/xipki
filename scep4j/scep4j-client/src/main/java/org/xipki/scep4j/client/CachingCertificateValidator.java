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
import java.util.concurrent.ConcurrentHashMap;

import org.xipki.scep4j.crypto.HashAlgoType;

/**
 * @author Lijun Liao
 */

public final class CachingCertificateValidator
implements CACertValidator
{
    private final ConcurrentHashMap<String, Boolean> cachedAnswers;
    private final CACertValidator delegate;

    public CachingCertificateValidator(
            final CACertValidator delegate)
            {
        this.delegate = delegate;
        this.cachedAnswers = new ConcurrentHashMap<String, Boolean>();
    }

    @Override
    public boolean isTrusted(
            final X509Certificate cert)
    {
        String hexFp;
        try
        {
            hexFp = HashAlgoType.SHA256.hexDigest(cert.getEncoded());
        } catch (CertificateEncodingException e)
        {
            return false;
        }

        if (cachedAnswers.containsKey(hexFp))
        {
            return cachedAnswers.get(cert);
        } else
        {
            boolean answer = delegate.isTrusted(cert);
            cachedAnswers.put(hexFp, answer);
            return answer;
        }
    }

}
