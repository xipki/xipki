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
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public class CrlSignerEntry
{
    private final String name;
    private String type;
    private String conf;
    private X509Certificate cert;
    private int period; // in minutes
    private int overlap; // in minutes
    private boolean includeCertsInCrl;
    private boolean includeExpiredCerts;

    public CrlSignerEntry(String name)
    {
        ParamChecker.assertNotEmpty("name", name);

        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public String getType()
    {
        return type;
    }

    public void setType(String type)
    {
        this.type = type;
    }

    public String getConf()
    {
        return conf;
    }

    public void setConf(String conf)
    {
        this.conf = conf;
    }

    public X509Certificate getCertificate()
    {
        return cert;
    }

    public void setCertificate(X509Certificate cert)
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
        sb.append("type: ").append(type).append('\n');
        sb.append("conf: ").append(conf).append('\n');
        sb.append("period: ").append(getPeriod()).append(" minutes\n");
        sb.append("overlap: ").append(getOverlap()).append(" minutes\n");
        sb.append("includeCertsInCrl: ").append(includeCertsInCrl ? "yes" : "no").append("\n");
        sb.append("includeExpiredCerts: ").append(includeExpiredCerts ? "yes" : "no").append('\n');
        sb.append("cert: ").append("\n");
        sb.append("\tissuer: ").append(
                IoCertUtil.canonicalizeName(cert.getIssuerX500Principal())).append('\n');
        sb.append("\tserialNumber: ").append(cert.getSerialNumber()).append('\n');
        sb.append("\tsubject: ").append(
                IoCertUtil.canonicalizeName(cert.getSubjectX500Principal())).append('\n');
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

    public int getPeriod()
    {
        return period;
    }

    public void setPeriod(int period)
    {
        this.period = period;
    }

    public int getOverlap()
    {
        return overlap;
    }

    public void setOverlap(int overlap)
    {
        this.overlap = overlap;
    }

    public boolean includeCertsInCRL()
    {
        return includeCertsInCrl;
    }

    public void setIncludeCertsInCrl(boolean includeCertsInCrl)
    throws ConfigurationException
    {
        this.includeCertsInCrl = includeCertsInCrl;
    }

    public boolean includeExpiredCerts()
    {
        return includeExpiredCerts;
    }

    public void setIncludeExpiredCerts(boolean includeExpiredCerts)
    {
        this.includeExpiredCerts = includeExpiredCerts;
    }

}
