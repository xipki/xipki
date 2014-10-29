/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.impl;

import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * @author Lijun Liao
 */

class CAInfo
{
    private final X509Certificate cert;
    private final Set<String> certProfiles;

    CAInfo(X509Certificate cert, Set<String> certProfiles)
    {
        this.cert = cert;
        this.certProfiles = certProfiles;
    }

    X509Certificate getCert()
    {
        return cert;
    }

    Set<String> getCertProfiles()
    {
        return certProfiles;
    }
}
