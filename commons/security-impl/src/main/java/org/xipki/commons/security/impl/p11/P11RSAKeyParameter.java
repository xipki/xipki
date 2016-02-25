/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.security.impl.p11;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11RSAKeyParameter extends RSAKeyParameters {

    private final P11CryptService p11CryptService;

    private final P11SlotIdentifier slot;

    private final P11KeyIdentifier keyId;

    private final int keysize;

    private P11RSAKeyParameter(
            final P11CryptService p11CryptService,
            final P11SlotIdentifier slot,
            final P11KeyIdentifier keyId,
            final BigInteger modulus,
            final BigInteger publicExponent) {
        super(true, modulus, publicExponent);

        this.p11CryptService = p11CryptService;
        this.slot = slot;
        this.keyId = keyId;
        this.keysize = modulus.bitLength();
    }

    public int getKeysize() {
        return keysize;
    }

    public P11CryptService getP11CryptService() {
        return p11CryptService;
    }

    public P11SlotIdentifier getSlot() {
        return slot;
    }

    public P11KeyIdentifier getKeyId() {
        return keyId;
    }

    public static P11RSAKeyParameter getInstance(
            final P11CryptService p11CryptService,
            final P11SlotIdentifier slot,
            final P11KeyIdentifier keyId)
    throws InvalidKeyException {
        ParamUtil.assertNotNull("p11CryptService", p11CryptService);
        ParamUtil.assertNotNull("slot", slot);
        ParamUtil.assertNotNull("keyId", keyId);

        RSAPublicKey key;
        try {
            key = (RSAPublicKey) p11CryptService.getPublicKey(slot, keyId);
        } catch (SignerException ex) {
            throw new InvalidKeyException(ex.getMessage(), ex);
        }

        BigInteger modulus = key.getModulus();
        BigInteger publicExponent = key.getPublicExponent();
        return new P11RSAKeyParameter(p11CryptService, slot, keyId, modulus, publicExponent);
    }

}
