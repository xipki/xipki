/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * @author Lijun Liao
 */

public abstract class KeypairGenerationResult
{
    private final X509CertificateHolder certificate;

    protected KeypairGenerationResult(X509CertificateHolder certificate)
    {
        this.certificate = certificate;
    }

    public X509CertificateHolder getCertificate()
    {
        return certificate;
    }

}
