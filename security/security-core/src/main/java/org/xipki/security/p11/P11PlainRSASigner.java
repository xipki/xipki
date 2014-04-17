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

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.xipki.security.api.SignerException;

public class P11PlainRSASigner implements AsymmetricBlockCipher
{
    private P11RSAKeyParameter param;

    public P11PlainRSASigner()
    {
    }

    @Override
    public void init(boolean forEncryption, CipherParameters param)
    {
        if(forEncryption == false)
        {
            throw new RuntimeCryptoException("Verification mode not supported.");
        }

        if(param instanceof P11RSAKeyParameter == false)
        {
            throw new IllegalArgumentException("invalid param type "  + param.getClass().getName());
        }
        this.param = (P11RSAKeyParameter) param;
    }

    @Override
    public int getInputBlockSize()
    {
        return (param.getKeysize() + 7) / 8;
    }

    @Override
    public int getOutputBlockSize()
    {
         return (param.getKeysize() + 7) / 8;
    }

    @Override
    public byte[] processBlock(byte[] in, int inOff, int len)
            throws InvalidCipherTextException
    {
        byte[] content = new byte[getInputBlockSize()];
        System.arraycopy(in, inOff, content, content.length-len, len);

        try {
            return param.getP11CryptService().CKM_RSA_X509(
                    content,
                    param.getSlot(),
                    param.getKeyId());
        } catch (SignerException e) {
            throw new InvalidCipherTextException(e.getMessage(), e);
        }
    }

}
