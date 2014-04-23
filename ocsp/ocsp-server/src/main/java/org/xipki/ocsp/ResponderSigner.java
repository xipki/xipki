/*
 * Copyright 2014 xipki.org
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

package org.xipki.ocsp;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.common.ParamChecker;

public class ResponderSigner
{
    private final ConcurrentContentSigner signer;

    private final X509CertificateHolder certificate;

    private final X500Name responderId;

    public ResponderSigner(ConcurrentContentSigner signer)
    throws CertificateEncodingException, IOException
    {
        ParamChecker.assertNotNull("signer", signer);

        this.signer = signer;
        this.certificate = new X509CertificateHolder(signer.getCertificate().getEncoded());
        this.responderId = this.certificate.getSubject();
    }

    public ConcurrentContentSigner getSigner()
    {
        return signer;
    }

    public X500Name getResponderId()
    {
        return responderId;
    }

    public X509CertificateHolder getCertificate()
    {
        return certificate;
    }

}
