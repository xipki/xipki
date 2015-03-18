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

package org.xipki.security.p11;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ParamChecker;
import org.xipki.security.SignerUtil;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class P11RSAPSSContentSigner implements ContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(P11RSAPSSContentSigner.class);
    private final AlgorithmIdentifier algorithmIdentifier;
    private final PSSSigner pssSigner;
    private final OutputStream outputStream;

    public P11RSAPSSContentSigner(
            P11CryptService cryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId,
            AlgorithmIdentifier signatureAlgId)
    throws NoSuchAlgorithmException, NoSuchPaddingException, OperatorCreationException
    {
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("signatureAlgId", signatureAlgId);
        ParamChecker.assertNotNull("keyId", keyId);

        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm()) == false)
        {
            throw new IllegalArgumentException("unsupported signature algorithm " + signatureAlgId.getAlgorithm());
        }

        this.algorithmIdentifier = signatureAlgId;

        AsymmetricBlockCipher cipher = new P11PlainRSASigner();

        P11RSAKeyParameter keyParam;
        try
        {
            keyParam = P11RSAKeyParameter.getInstance(cryptService, slot, keyId);
        } catch (InvalidKeyException e)
        {
            throw new OperatorCreationException(e.getMessage(), e);
        }

        this.pssSigner = SignerUtil.createPSSRSASigner(signatureAlgId, cipher);
        this.pssSigner.init(true, keyParam);

        this.outputStream = new PSSSignerOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream()
    {
        pssSigner.reset();
        return outputStream;
    }

    @Override
    public byte[] getSignature()
    {
        try
        {
            return pssSigner.generateSignature();
        } catch (CryptoException e)
        {
            LOG.warn("SignerException: {}", e.getMessage());
            LOG.debug("SignerException", e);
            throw new RuntimeCryptoException("SignerException: " + e.getMessage());
        }
    }

    private class PSSSignerOutputStream extends OutputStream
    {

        @Override
        public void write(int b)
        throws IOException
        {
            pssSigner.update((byte) b);
        }

        @Override
        public void write(byte[] b)
        throws IOException
        {
            pssSigner.update(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len)
        throws IOException
        {
            pssSigner.update(b, off, len);
        }

        @Override
        public void flush()
        throws IOException
        {
        }

        @Override
        public void close()
        throws IOException
        {
        }
    }

}
