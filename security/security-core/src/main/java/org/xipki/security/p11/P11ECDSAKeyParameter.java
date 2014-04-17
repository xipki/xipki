/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.p11;

import java.security.InvalidKeyException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.common.ParamChecker;

public class P11ECDSAKeyParameter extends AsymmetricKeyParameter
{
    private final P11CryptService p11CryptService;

    private final PKCS11SlotIdentifier slot;
    private final Pkcs11KeyIdentifier keyId;

    private P11ECDSAKeyParameter(P11CryptService p11CryptService,
            PKCS11SlotIdentifier slot,
            Pkcs11KeyIdentifier keyId)
    {
        super(true);

        this.p11CryptService = p11CryptService;
        this.slot = slot;
        this.keyId = keyId;
    }

    public static P11ECDSAKeyParameter getInstance(
            P11CryptService p11CryptService,
            PKCS11SlotIdentifier slot,
            Pkcs11KeyIdentifier keyId)
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

    public PKCS11SlotIdentifier getSlot()
    {
        return slot;
    }

    public Pkcs11KeyIdentifier getKeyId()
    {
        return keyId;
    }

}
