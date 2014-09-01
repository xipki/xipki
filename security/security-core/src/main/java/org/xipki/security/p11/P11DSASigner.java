/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import org.bouncycastle.crypto.Digest;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class P11DSASigner extends AbstractP11DSASigner
{
    public P11DSASigner(Digest digest)
    {
        super(digest);
    }

    @Override
    protected byte[] sign(byte[] hashValue)
    throws SignerException
    {
        return param.getP11CryptService().CKM_DSA(hashValue, param.getSlot(), param.getKeyId());
    }

}
