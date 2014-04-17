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

import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.SignerUtil;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

public class P11ECDSAContentSigner implements ContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(P11ECDSAContentSigner.class);

    private final AlgorithmIdentifier algorithmIdentifier;
    private final DigestOutputStream outputStream;

    private final P11CryptService cryptService;
    private final PKCS11SlotIdentifier slot;
    private final Pkcs11KeyIdentifier keyId;

    public P11ECDSAContentSigner(
            P11CryptService cryptService,
            PKCS11SlotIdentifier slot,
            Pkcs11KeyIdentifier keyId,
            AlgorithmIdentifier signatureAlgId)
    throws NoSuchAlgorithmException, OperatorCreationException
    {
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("keyId", keyId);
        ParamChecker.assertNotNull("signatureAlgId", signatureAlgId);

        this.slot = slot;
        this.algorithmIdentifier = signatureAlgId;
        this.keyId = keyId;
        this.cryptService = cryptService;

        AlgorithmIdentifier digAlgId = SignerUtil.extractDigesetAlgorithmIdentifier(signatureAlgId);

        Digest digest = BcDefaultDigestProvider.INSTANCE.get(digAlgId);

        this.outputStream = new DigestOutputStream(digest);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        outputStream.reset();
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        byte[] hashValue = outputStream.digest();
        try {
            return cryptService.CKM_ECDSA(hashValue, slot, keyId);
        } catch (SignerException e) {
            LOG.warn("SignerException: {}", e.getMessage());
            LOG.debug("SignerException", e);
            throw new RuntimeCryptoException("SignerException: " + e.getMessage());
        } catch (Throwable t) {
            LOG.warn("Throwable: {}", t.getMessage());
            LOG.debug("Throwable", t);
            throw new RuntimeCryptoException("IOException: " + t.getMessage());
        }
    }

}
