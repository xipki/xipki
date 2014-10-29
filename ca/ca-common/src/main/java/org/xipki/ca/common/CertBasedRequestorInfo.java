/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertBasedRequestorInfo implements RequestorInfo
{
    private final String name;
    private final X509CertificateWithMetaInfo certificate;
    private final boolean ra;

    public CertBasedRequestorInfo(String name, X509CertificateWithMetaInfo certificate, boolean ra)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotNull("certificate", certificate);

        this.name = name;
        this.certificate = certificate;
        this.ra = ra;
    }

    public X509CertificateWithMetaInfo getCertificate()
    {
        return certificate;
    }

    @Override
    public boolean isRA()
    {
        return ra;
    }

    @Override
    public String getName()
    {
        return name;
    }

}
