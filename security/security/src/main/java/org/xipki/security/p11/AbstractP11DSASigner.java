/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.Signer;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

abstract class AbstractP11DSASigner implements Signer
{
    private final Digest digest;
    protected P11KeyParameter param;

    protected abstract byte[] sign(byte[] hashValue)
    throws SignerException;

    public AbstractP11DSASigner(Digest digest)
    {
        ParamChecker.assertNotNull("digest", digest);
        this.digest = digest;
    }

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if(forSigning == false)
        {
            throw new RuntimeCryptoException("Verification mode not supported.");
        }

        if(param instanceof P11KeyParameter == false)
        {
            throw new IllegalArgumentException("invalid param type "  + param.getClass().getName());
        }
        this.param = (P11KeyParameter) param;
        reset();
    }

    @Override
    public void update(byte b)
    {
        digest.update(b);
    }

    @Override
    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    @Override
    public byte[] generateSignature()
    throws CryptoException, DataLengthException
    {
        byte[] digestValue = new byte[digest.getDigestSize()];
        digest.doFinal(digestValue, 0);

        try
        {
            return sign(digestValue);
        } catch (SignerException e)
        {
            throw new InvalidCipherTextException("SignerException: " + e.getMessage());
        }
    }

    @Override
    public boolean verifySignature(byte[] signature)
    {
        throw new UnsupportedOperationException("verifySignature not supported");
    }

    @Override
    public void reset()
    {
        digest.reset();
    }

}
