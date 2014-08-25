/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import org.bouncycastle.cert.X509CertificateHolder;
import org.xipki.security.api.KeypairGenerationResult;

/**
 * @author Lijun Liao
 */

public class P12KeypairGenerationResult extends KeypairGenerationResult
{
    private final byte[] keystore;

    public P12KeypairGenerationResult(byte[] keystore, X509CertificateHolder certificate)
    {
        super(certificate);
        this.keystore = keystore;
    }

    public byte[] getKeystore()
    {
        return keystore;
    }

}
