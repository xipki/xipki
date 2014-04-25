/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.ca.server;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

public class PublicCAInfo
{
    private final X509Certificate caCertificate;
    private X509Certificate crlSignerCertificate;
    private final List<String> ocspUris;
    private final List<String> crlUris;
    private final List<String> caIssuerLocations;

    public PublicCAInfo(X509Certificate caCertificate,
            List<String> ocspUris, List<String> crlUris,
            List<String> caIssuerLocations)
    {
        this.caCertificate = caCertificate;
        this.ocspUris = ocspUris;
        this.crlUris = crlUris;
        this.caIssuerLocations = caIssuerLocations;
    }

    public X509Certificate getCACertificate()
    {
        return caCertificate;
    }

    public List<String> getOcspUris()
    {
        return ocspUris == null ? null : Collections.unmodifiableList(ocspUris);
    }

    public List<String> getCrlUris()
    {
        return crlUris == null ? null : Collections.unmodifiableList(crlUris);
    }

    public List<String> getCaIssuerLocations()
    {
        return caIssuerLocations == null ? null : Collections.unmodifiableList(caIssuerLocations);
    }

    public X509Certificate getCrlSignerCertificate()
    {
        return crlSignerCertificate;
    }

    public void setCrlSignerCertificate(X509Certificate crlSignerCert)
    {
        if(caCertificate.equals(crlSignerCert))
        {
            this.crlSignerCertificate = null;
        }
        else
        {
            this.crlSignerCertificate = crlSignerCert;
        }
    }
}
