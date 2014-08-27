/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11RSAKeyParameter extends RSAKeyParameters
{
    private final P11CryptService p11CryptService;

    private final P11SlotIdentifier slot;
    private final P11KeyIdentifier keyId;

    private final int keysize;

    private P11RSAKeyParameter(P11CryptService p11CryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId,
            BigInteger modulus, BigInteger publicExponent)
    {
        super(true, modulus, publicExponent);

        this.p11CryptService = p11CryptService;
        this.slot = slot;
        this.keyId = keyId;
        this.keysize = modulus.bitLength();
    }

    public static P11RSAKeyParameter getInstance(
            P11CryptService p11CryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId)
    throws InvalidKeyException
    {
        ParamChecker.assertNotNull("p11CryptService", p11CryptService);
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("keyId", keyId);

        RSAPublicKey key;
        try
        {
            key = (RSAPublicKey) p11CryptService.getPublicKey(slot, keyId);
        } catch (SignerException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }

        BigInteger modulus = key.getModulus();
        BigInteger publicExponent = key.getPublicExponent();
        return new P11RSAKeyParameter(p11CryptService, slot, keyId, modulus, publicExponent);
    }

    public int getKeysize()
    {
        return keysize;
    }

    public P11CryptService getP11CryptService()
    {
        return p11CryptService;
    }

    public P11SlotIdentifier getSlot()
    {
        return slot;
    }

    public P11KeyIdentifier getKeyId()
    {
        return keyId;
    }

}
