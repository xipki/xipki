/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import java.security.KeyStore;

import org.bouncycastle.cert.X509CertificateHolder;
import org.xipki.security.api.KeypairGenerationResult;

/**
 * @author Lijun Liao
 */

public class P12KeypairGenerationResult extends KeypairGenerationResult
{
    private final byte[] keystore;
    private KeyStore keystoreObject;

    public P12KeypairGenerationResult(byte[] keystore, X509CertificateHolder certificate)
    {
        super(certificate);
        this.keystore = keystore;
    }

    public byte[] getKeystore()
    {
        return keystore;
    }

    public KeyStore getKeystoreObject()
    {
        return keystoreObject;
    }

    public void setKeystoreObject(KeyStore keystoreObject)
    {
        this.keystoreObject = keystoreObject;
    }

}
