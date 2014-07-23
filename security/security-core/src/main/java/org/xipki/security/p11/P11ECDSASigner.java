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
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11ECDSASigner implements Signer
{
    private final Digest digest;
    private P11ECDSAKeyParameter param;

    public P11ECDSASigner(Digest digest)
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

        if(param instanceof P11ECDSAKeyParameter == false)
        {
            throw new IllegalArgumentException("invalid param type "  + param.getClass().getName());
        }
        this.param = (P11ECDSAKeyParameter) param;
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
            return param.getP11CryptService().CKM_ECDSA(digestValue, param.getSlot(), param.getKeyId());
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
