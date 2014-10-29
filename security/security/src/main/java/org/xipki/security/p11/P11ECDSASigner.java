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

public class P11ECDSASigner extends AbstractP11DSASigner
{
    public P11ECDSASigner(Digest digest)
    {
        super(digest);
    }

    @Override
    protected byte[] sign(byte[] hashValue)
    throws SignerException
    {
        return param.getP11CryptService().CKM_ECDSA(hashValue, param.getSlot(), param.getKeyId());
    }

}
