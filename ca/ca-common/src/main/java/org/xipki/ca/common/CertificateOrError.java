/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import java.security.cert.Certificate;

import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertificateOrError
{
    private final Certificate certificate;
    private final PKIStatusInfo error;

    public CertificateOrError(Certificate certificate)
    {
        ParamChecker.assertNotNull("certificate", certificate);

        this.certificate = certificate;
        this.error = null;
    }

    public CertificateOrError(PKIStatusInfo error)
    {
        ParamChecker.assertNotNull("error", error);

        this.certificate = null;
        this.error = error;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public PKIStatusInfo getError()
    {
        return error;
    }

}
