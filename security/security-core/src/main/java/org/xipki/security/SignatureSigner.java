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

package org.xipki.security;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.security.common.ParamChecker;

public class SignatureSigner implements ContentSigner
{
    private final AlgorithmIdentifier sigAlgId;
    private final Signature signer;
    private final SignatureStream stream = new SignatureStream();

    public SignatureSigner(AlgorithmIdentifier sigAlgId, Signature signer)
    {
        ParamChecker.assertNotNull("sigAlgId", sigAlgId);
        ParamChecker.assertNotNull("signer", signer);

        this.sigAlgId = sigAlgId;
        this.signer = signer;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return sigAlgId;
    }

    @Override
    public OutputStream getOutputStream()
    {
        return stream;
    }

    @Override
    public byte[] getSignature()
    {
        try
        {
            return stream.getSignature();
        }
        catch (SignatureException e)
        {
            throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
        }
    }

    private class SignatureStream extends OutputStream
    {
        public byte[] getSignature()
        throws SignatureException
        {
            return signer.sign();
        }

        @Override
        public void write(int b)
        throws IOException
        {
            try
            {
                signer.update((byte) b);
            }catch(SignatureException e)
            {
                throw new IOException(e);
            }
        }

        @Override
        public void write(byte[] b)
        throws IOException
        {
            try
            {
                signer.update(b);
            }catch(SignatureException e)
            {
                throw new IOException(e);
            }
        }

        @Override
        public void write(byte[] b, int off, int len)
        throws IOException
        {
            try
            {
                signer.update(b, off, len);
            }catch(SignatureException e)
            {
                throw new IOException(e);
            }
        }
    }

}
