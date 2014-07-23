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
    private final X509Certificate cert;
    private final X509Certificate responder;
    private final X500Name subject;
    private final Set<String> profiles;

    CAConf(String name, String url, X509Certificate cert, Set<String> profiles, X509Certificate responder)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("url", url);
        ParamChecker.assertNotNull("cert", cert);
        ParamChecker.assertNotNull("responder", responder);

        this.name = name;
        this.url = url;
        this.cert = cert;
        this.subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        if(profiles == null)
        {
            this.profiles = Collections.emptySet();
        }
        else
        {
            this.profiles = profiles;
        }
        this.responder = responder;
    }

    public String getName()
    {
        return name;
    }

    public String getUrl()
    {
        return url;
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

    public X509Certificate getResponder()
    {
        return responder;
    }
}
