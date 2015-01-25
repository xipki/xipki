/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.client.impl;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.client.api.CertProfileInfo;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CAConf
{
    private final String name;
    private final String url;
    private final String healthUrl;
    private final String requestorName;
    private X509CmpRequestor requestor;

    private boolean certAutoconf;
    private boolean certprofilesAutoconf;

    private X509Certificate cert;
    private X509Certificate responder;
    private X500Name subject;
    private Map<String, CertProfileInfo> profiles = Collections.emptyMap();

    CAConf(String name, String url, String healthUrl, String requestorName)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("url", url);
        ParamChecker.assertNotEmpty("requestorName", requestorName);

        this.name = name;
        this.url = url;
        this.requestorName = requestorName;
        if(healthUrl == null || healthUrl.isEmpty())
        {
            this.healthUrl = url.replace("cmp", "health");
        }
        else
        {
            this.healthUrl = healthUrl;
        }
    }

    public String getName()
    {
        return name;
    }

    public String getUrl()
    {
        return url;
    }

    public String getHealthUrl()
    {
        return healthUrl;
    }

    public void setCert(X509Certificate cert)
    {
        this.cert = cert;
        if(cert != null)
        {
            this.subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        }
        else
        {
            this.subject = null;
        }
    }

    public void setCertprofiles(Set<CertProfileInfo> profiles)
    {
        if(profiles == null)
        {
            this.profiles = Collections.emptyMap();
        }
        else
        {
            this.profiles = new HashMap<>();
            for(CertProfileInfo m : profiles)
            {
                this.profiles.put(m.getName(), m);
            }
        }
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public Set<String> getProfileNames()
    {
        return profiles.keySet();
    }

    public boolean supportsProfile(String profileName)
    {
        return profiles.containsKey(profileName);
    }

    public CertProfileInfo getProfile(String profileName)
    {
        return profiles.get(profileName);
    }

    public boolean isCAInfoConfigured()
    {
        return cert != null;
    }

    public void setResponder(X509Certificate responder)
    {
        this.responder = responder;
    }

    public X509Certificate getResponder()
    {
        return responder;
    }

    public boolean isCertAutoconf()
    {
        return certAutoconf;
    }

    public void setCertAutoconf(boolean autoconf)
    {
        this.certAutoconf = autoconf;
    }

    public boolean isCertprofilesAutoconf()
    {
        return certprofilesAutoconf;
    }

    public void setCertprofilesAutoconf(boolean autoconf)
    {
        this.certprofilesAutoconf = autoconf;
    }

    public void setRequestor(X509CmpRequestor requestor)
    {
        this.requestor = requestor;
    }

    public String getRequestorName()
    {
        return requestorName;
    }

    public X509CmpRequestor getRequestor()
    {
        return requestor;
    }
}
