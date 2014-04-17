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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

public class P11RSAKeyParameter extends RSAKeyParameters {
    private final P11CryptService p11CryptService;

    private final PKCS11SlotIdentifier slot;
    private final Pkcs11KeyIdentifier keyId;

    private final int keysize;

    private P11RSAKeyParameter(P11CryptService p11CryptService,
            PKCS11SlotIdentifier slot,
            Pkcs11KeyIdentifier keyId,
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
            PKCS11SlotIdentifier slot,
            Pkcs11KeyIdentifier keyId)
    throws InvalidKeyException
    {
        ParamChecker.assertNotNull("p11CryptService", p11CryptService);
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("keyId", keyId);

        RSAPublicKey key;
        try {
            key = (RSAPublicKey) p11CryptService.getPublicKey(slot, keyId);
        } catch (SignerException e) {
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

    public P11CryptService getP11CryptService() {
        return p11CryptService;
    }

    public PKCS11SlotIdentifier getSlot() {
        return slot;
    }

    public Pkcs11KeyIdentifier getKeyId()
    {
        return keyId;
    }

}
