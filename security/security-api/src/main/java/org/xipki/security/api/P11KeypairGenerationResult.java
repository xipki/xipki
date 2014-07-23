/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import java.util.Arrays;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * @author Lijun Liao
 */

public class P11KeypairGenerationResult extends KeypairGenerationResult
{
    private final byte[] id;
    private final String label;

    public P11KeypairGenerationResult(byte[] id, String label, X509CertificateHolder certificate)
    {
        super(certificate);
        this.id = id;
        this.label = label;
    }

    public byte[] getId()
    {
        return Arrays.copyOf(id, id.length);
    }

    public String getLabel()
    {
        return label;
    }

}
