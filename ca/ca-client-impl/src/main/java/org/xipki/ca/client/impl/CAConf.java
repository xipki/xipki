/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.impl;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CAConf
{
    private final String name;
    private final String url;
    private X509CmpRequestor requestor;

    private boolean autoConf;
    private X509Certificate cert;
    private X509Certificate responder;
    private X500Name subject;
    private Set<String> profiles = Collections.emptySet();

    CAConf(String name, String url)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("url", url);

        this.name = name;
        this.url = url;
    }

    public String getName()
    {
        return name;
    }

    public String getUrl()
    {
        return url;
    }

    public void setCAInfo(X509Certificate cert, Set<String> profiles)
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

        if(profiles == null)
        {
            this.profiles = Collections.emptySet();
        }
        else
        {
            this.profiles = profiles;
        }
    }

    public void setCAInfo(CAInfo caInfo)
    {
        setCAInfo(caInfo.getCert(), caInfo.getCertProfiles());
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public Set<String> getProfiles()
    {
        return profiles;
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

    public boolean isAutoConf()
    {
        return autoConf;
    }

    public void setAutoConf(boolean autoConf)
    {
        this.autoConf = autoConf;
    }

    public void setRequestor(X509CmpRequestor requestor)
    {
        this.requestor = requestor;
    }

    public X509CmpRequestor getRequestor()
    {
        return requestor;
    }
}
