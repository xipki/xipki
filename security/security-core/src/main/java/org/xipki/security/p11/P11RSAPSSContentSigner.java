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
import org.xipki.security.SignerUtil;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.common.ParamChecker;

public class P11RSAPSSContentSigner implements ContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(P11RSAPSSContentSigner.class);
    private final AlgorithmIdentifier algorithmIdentifier;
    private final PSSSigner pssSigner;
    private final OutputStream outputStream;

    public P11RSAPSSContentSigner(
            P11CryptService cryptService,
            PKCS11SlotIdentifier slot,
            Pkcs11KeyIdentifier keyId,
            AlgorithmIdentifier signatureAlgId)
            throws NoSuchAlgorithmException, NoSuchPaddingException, OperatorCreationException
    {
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("signatureAlgId", signatureAlgId);
        ParamChecker.assertNotNull("keyId", keyId);

        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm()) == false)
        {
            throw new IllegalArgumentException("Unsupported signature algorithm " + signatureAlgId.getAlgorithm());
        }

        this.algorithmIdentifier = signatureAlgId;

        AsymmetricBlockCipher cipher = new P11PlainRSASigner();

        P11RSAKeyParameter keyParam;
        try {
            keyParam = P11RSAKeyParameter.getInstance(cryptService, slot, keyId);
        } catch (InvalidKeyException e) {
            throw new OperatorCreationException(e.getMessage(), e);
        }


        this.pssSigner = SignerUtil.createPSSRSASigner(signatureAlgId, cipher);
        this.pssSigner.init(true, keyParam);

        this.outputStream = new PSSSignerOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        pssSigner.reset();
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            return pssSigner.generateSignature();
        } catch (CryptoException e) {
            LOG.warn("SignerException: {}", e.getMessage());
            LOG.debug("SignerException", e);
            throw new RuntimeCryptoException("SignerException: " + e.getMessage());
        }
    }

    private class PSSSignerOutputStream extends OutputStream
    {

        @Override
        public void write(int b) throws IOException {
            pssSigner.update((byte) b);
        }

        @Override
        public void write(byte[] b) throws IOException {
            pssSigner.update(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            pssSigner.update(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            ;
        }

        @Override
        public void close() throws IOException {
        }
    }

}
