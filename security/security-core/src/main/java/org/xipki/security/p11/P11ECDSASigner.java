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

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.Signer;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

public class P11ECDSASigner implements Signer {
    private final Digest digest;
    private P11ECDSAKeyParameter param;

    public P11ECDSASigner(Digest digest)
    {
        ParamChecker.assertNotNull("digest", digest);
        this.digest = digest;
    }

    @Override
    public void init(boolean forSigning, CipherParameters param) {
        if(forSigning == false)
        {
            throw new RuntimeCryptoException("Verification mode not supported.");
        }

        if(param instanceof P11ECDSAKeyParameter == false)
        {
            throw new IllegalArgumentException("invalid param type "  + param.getClass().getName());
        }
        this.param = (P11ECDSAKeyParameter) param;
        reset();
    }

    @Override
    public void update(byte b) {
        digest.update(b);
    }

    @Override
    public void update(byte[] in, int off, int len) {
        digest.update(in, off, len);
    }

    @Override
    public byte[] generateSignature() throws CryptoException,
            DataLengthException
    {
        byte[] digestValue = new byte[digest.getDigestSize()];
        digest.doFinal(digestValue, 0);

        try
        {
            return param.getP11CryptService().CKM_ECDSA(digestValue, param.getSlot(), param.getKeyId());
        } catch (SignerException e) {
            throw new InvalidCipherTextException("SignerException: " + e.getMessage());
        }
    }

    @Override
    public boolean verifySignature(byte[] signature) {
        throw new UnsupportedOperationException("verifySignature not supported");
    }

    @Override
    public void reset() {
        digest.reset();
    }

}
