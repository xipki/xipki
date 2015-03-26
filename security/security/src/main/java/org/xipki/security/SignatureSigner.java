/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class SignatureSigner implements ContentSigner
{
    private final AlgorithmIdentifier sigAlgId;
    private final Signature signer;
    private final SignatureStream stream = new SignatureStream();
    private final PrivateKey key;

    public SignatureSigner(
            final AlgorithmIdentifier sigAlgId,
            final Signature signer,
            final PrivateKey key)
    {
        ParamChecker.assertNotNull("sigAlgId", sigAlgId);
        ParamChecker.assertNotNull("signer", signer);
        ParamChecker.assertNotNull("key", key);

        this.sigAlgId = sigAlgId;
        this.signer = signer;
        this.key = key;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return sigAlgId;
    }

    @Override
    public OutputStream getOutputStream()
    {
        try
        {
            signer.initSign(key);
        } catch (InvalidKeyException e)
        {
            throw new RuntimeOperatorException("could not initSign", e);
        }
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
        public void write(
                final int b)
        throws IOException
        {
            try
            {
                signer.update((byte) b);
            }catch(SignatureException e)
            {
                throw new IOException(e.getMessage(), e);
            }
        }

        @Override
        public void write(
                final byte[] b)
        throws IOException
        {
            try
            {
                signer.update(b);
            }catch(SignatureException e)
            {
                throw new IOException(e.getMessage(), e);
            }
        }

        @Override
        public void write(
                final byte[] b,
                final int off,
                final int len)
        throws IOException
        {
            try
            {
                signer.update(b, off, len);
            }catch(SignatureException e)
            {
                throw new IOException(e.getMessage(), e);
            }
        }
    }

}
