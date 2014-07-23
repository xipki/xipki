/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.impl.digest;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.operator.DigestCalculator;

/**
 * @author Lijun Liao
 */

public abstract class AbstractDigestCalculator implements DigestCalculator
{
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    protected abstract ASN1ObjectIdentifier getObjectIdentifier();
    protected abstract Digest getDigester();

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(getObjectIdentifier());
    }

    public OutputStream getOutputStream()
    {
        return bOut;
    }

    public byte[] getDigest()
    {
        byte[] bytes = bOut.toByteArray();

        bOut.reset();

        Digest digester = getDigester();

        digester.update(bytes, 0, bytes.length);

        byte[] digest = new byte[digester.getDigestSize()];

        digester.doFinal(digest, 0);

        return digest;
    }

}
