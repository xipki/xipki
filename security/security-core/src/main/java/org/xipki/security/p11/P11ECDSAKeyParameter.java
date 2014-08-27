/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.security.InvalidKeyException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11ECDSAKeyParameter extends AsymmetricKeyParameter
{
    private final P11CryptService p11CryptService;

    private final P11SlotIdentifier slot;
    private final P11KeyIdentifier keyId;

    private P11ECDSAKeyParameter(P11CryptService p11CryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId)
    {
        super(true);

        this.p11CryptService = p11CryptService;
        this.slot = slot;
        this.keyId = keyId;
    }

    public static P11ECDSAKeyParameter getInstance(
            P11CryptService p11CryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId)
    throws InvalidKeyException
    {
        ParamChecker.assertNotNull("p11CryptService", p11CryptService);
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("keyId", keyId);

        return new P11ECDSAKeyParameter(p11CryptService, slot, keyId);
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
