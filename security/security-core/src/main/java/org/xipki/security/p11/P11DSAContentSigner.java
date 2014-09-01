/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class P11DSAContentSigner extends AbstractP11DSAContentSigner
{
    public P11DSAContentSigner(
            P11CryptService cryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId,
            AlgorithmIdentifier signatureAlgId)
    throws NoSuchAlgorithmException, OperatorCreationException
    {
        super(cryptService, slot, keyId, signatureAlgId);
    }

    @Override
    protected byte[] CKM_SIGN(byte[] hashValue)
    throws SignerException
    {
        return cryptService.CKM_DSA(hashValue, slot, keyId);
    }

}
