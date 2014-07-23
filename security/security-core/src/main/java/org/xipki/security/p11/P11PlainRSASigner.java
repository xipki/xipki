/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class P11PlainRSASigner implements AsymmetricBlockCipher
{
    private P11RSAKeyParameter param;

    public P11PlainRSASigner()
    {
    }

    @Override
    public void init(boolean forEncryption, CipherParameters param)
    {
        if(forEncryption == false)
        {
            throw new RuntimeCryptoException("Verification mode not supported.");
        }

        if(param instanceof P11RSAKeyParameter == false)
        {
            throw new IllegalArgumentException("invalid param type "  + param.getClass().getName());
        }
        this.param = (P11RSAKeyParameter) param;
    }

    @Override
    public int getInputBlockSize()
    {
        return (param.getKeysize() + 7) / 8;
    }

    @Override
    public int getOutputBlockSize()
    {
         return (param.getKeysize() + 7) / 8;
    }

    @Override
    public byte[] processBlock(byte[] in, int inOff, int len)
    throws InvalidCipherTextException
    {
        byte[] content = new byte[getInputBlockSize()];
        System.arraycopy(in, inOff, content, content.length-len, len);

        try
        {
            return param.getP11CryptService().CKM_RSA_X509(
                    content,
                    param.getSlot(),
                    param.getKeyId());
        } catch (SignerException e)
        {
            throw new InvalidCipherTextException(e.getMessage(), e);
        }
    }

}
