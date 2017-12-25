/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11RSAKeyParameter extends RSAKeyParameters {

    private final P11CryptService p11CryptService;

    private final P11EntityIdentifier identityId;

    private final int keysize;

    private P11RSAKeyParameter(final P11CryptService p11CryptService,
            final P11EntityIdentifier identityId, final BigInteger modulus,
            final BigInteger publicExponent) {
        super(true, modulus, publicExponent);

        ParamUtil.requireNonNull("modulus", modulus);
        ParamUtil.requireNonNull("publicExponent", publicExponent);
        this.p11CryptService = ParamUtil.requireNonNull("p11CryptService", p11CryptService);
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        this.keysize = modulus.bitLength();
    }

    int keysize() {
        return keysize;
    }

    P11CryptService p11CryptService() {
        return p11CryptService;
    }

    P11EntityIdentifier identityId() {
        return identityId;
    }

    public static P11RSAKeyParameter getInstance(final P11CryptService p11CryptService,
            final P11EntityIdentifier identityId) throws InvalidKeyException {
        ParamUtil.requireNonNull("p11CryptService", p11CryptService);
        ParamUtil.requireNonNull("identityId", identityId);

        RSAPublicKey key;
        try {
            key = (RSAPublicKey) p11CryptService.getIdentity(identityId).publicKey();
        } catch (P11TokenException ex) {
            throw new InvalidKeyException(ex.getMessage(), ex);
        }

        BigInteger modulus = key.getModulus();
        BigInteger publicExponent = key.getPublicExponent();
        return new P11RSAKeyParameter(p11CryptService, identityId, modulus, publicExponent);
    }

}
