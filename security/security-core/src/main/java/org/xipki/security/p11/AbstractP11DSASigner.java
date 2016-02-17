/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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

package org.xipki.security.p11;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.Signer;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

abstract class AbstractP11DSASigner implements Signer
{
    private final Digest digest;
    protected P11KeyParameter param;

    protected abstract byte[] sign(byte[] hashValue)
    throws SignerException;

    public AbstractP11DSASigner(Digest digest)
    {
        ParamChecker.assertNotNull("digest", digest);
        this.digest = digest;
    }

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if(forSigning == false)
        {
            throw new RuntimeCryptoException("Verification mode not supported.");
        }

        if(param instanceof P11KeyParameter == false)
        {
            throw new IllegalArgumentException("invalid param type "  + param.getClass().getName());
        }
        this.param = (P11KeyParameter) param;
        reset();
    }

    @Override
    public void update(byte b)
    {
        digest.update(b);
    }

    @Override
    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    @Override
    public byte[] generateSignature()
    throws CryptoException, DataLengthException
    {
        byte[] digestValue = new byte[digest.getDigestSize()];
        digest.doFinal(digestValue, 0);

        try
        {
            return sign(digestValue);
        } catch (SignerException e)
        {
            throw new InvalidCipherTextException("SignerException: " + e.getMessage());
        }
    }

    @Override
    public boolean verifySignature(byte[] signature)
    {
        throw new UnsupportedOperationException("verifySignature not supported");
    }

    @Override
    public void reset()
    {
        digest.reset();
    }

}
