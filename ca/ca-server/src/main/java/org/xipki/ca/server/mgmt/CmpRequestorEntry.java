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

package org.xipki.ca.server.mgmt;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public class CmpRequestorEntry
{
    private final String name;
    private X509Certificate cert;

    public CmpRequestorEntry(String name)
    {
        ParamChecker.assertNotEmpty("name", name);
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public void setCert(X509Certificate cert)
    {
        this.cert = cert;
    }

    @Override
    public String toString()
    {
        return toString(false);
    }

    public String toString(boolean verbose)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("cert: ").append("\n");
        sb.append("\tissuer: ").append(
                IoCertUtil.canonicalizeName(cert.getIssuerX500Principal())).append("\n");
        sb.append("\tserialNumber: ").append(cert.getSerialNumber()).append("\n");
        sb.append("\tsubject: ").append(
                IoCertUtil.canonicalizeName(cert.getSubjectX500Principal()));
        if(verbose)
        {
            sb.append("\tencoded: ");
            try
            {
                sb.append(Base64.toBase64String(cert.getEncoded()));
            } catch (CertificateEncodingException e)
            {
                sb.append("ERROR");
            }
        }

        return sb.toString();
    }

}
