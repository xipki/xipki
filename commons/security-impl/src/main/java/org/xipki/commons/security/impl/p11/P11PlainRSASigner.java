/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
//CHECKSTYLE:SKIP
public class P11PlainRSASigner implements AsymmetricBlockCipher {

    private P11RSAKeyParameter param;

    public P11PlainRSASigner() {
    }

    @Override
    public void init(
            final boolean forEncryption,
            final CipherParameters cipherParam) {
        if (!forEncryption) {
            throw new RuntimeCryptoException("verification mode not supported.");
        }

        if (!(cipherParam instanceof P11RSAKeyParameter)) {
            throw new IllegalArgumentException(
                    "invalid param type " + cipherParam.getClass().getName());
        }
        this.param = (P11RSAKeyParameter) cipherParam;
    }

    @Override
    public int getInputBlockSize() {
        return (param.getKeysize() + 7) / 8;
    }

    @Override
    public int getOutputBlockSize() {
        return (param.getKeysize() + 7) / 8;
    }

    @Override
    public byte[] processBlock(
            final byte[] in,
            final int inOff,
            final int len)
    throws InvalidCipherTextException {
        byte[] content = new byte[getInputBlockSize()];
        System.arraycopy(in, inOff, content, content.length - len, len);

        try {
            return param.getP11CryptService().getIdentity(param.getIdentityId()).sign(
                    P11Constants.CKM_RSA_X_509, null, content);
        } catch (SecurityException | P11TokenException ex) {
            throw new InvalidCipherTextException(ex.getMessage(), ex);
        }
    }

}
