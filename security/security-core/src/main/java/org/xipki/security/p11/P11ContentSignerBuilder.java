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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.DefaultConcurrentContentSigner;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;
import org.xipki.security.provider.P11PrivateKey;

public class P11ContentSignerBuilder
{
    private final X509Certificate cert;

    private final P11CryptService cryptService;
    private final PKCS11SlotIdentifier slot;
    private final Pkcs11KeyIdentifier keyId;

    public P11ContentSignerBuilder(
            P11CryptService cryptService,
            PKCS11SlotIdentifier slot, char[] password,
            Pkcs11KeyIdentifier keyId,
            X509Certificate cert)
    throws SignerException
    {
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("keyId", keyId);

        this.cryptService = cryptService;
        this.keyId = keyId;
        this.slot = slot;

        boolean keyExists = false;
        if(cert != null)
        {
            this.cert = cert;
        }
        else
        {
            this.cert = this.cryptService.getCertificate(slot, keyId);
            keyExists = (this.cert != null);
        }

        if(keyExists == false)
        {
            keyExists = (this.cryptService.getPublicKey(slot, keyId) != null);
        }

        if(keyExists == false)
        {
            throw new SignerException("Key with " + keyId + " does not exist");
        }
    }

    public ConcurrentContentSigner createSigner(
            AlgorithmIdentifier signatureAlgId,
            int parallelism)
    throws OperatorCreationException, NoSuchPaddingException
    {
        if(parallelism < 1)
        {
            throw new IllegalArgumentException("non-positive parallelism is not allowed: " + parallelism);
        }

        List<ContentSigner> signers = new ArrayList<ContentSigner>(parallelism);

        PublicKey publicKey = cert.getPublicKey();
        try
        {
            for(int i = 0; i < parallelism; i++)
            {
                ContentSigner signer;
                if(publicKey instanceof RSAPublicKey)
                {
                    if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm()))
                    {
                        signer = new P11RSAPSSContentSigner(cryptService, slot, keyId, signatureAlgId);
                    }
                    else
                    {
                        signer = new P11RSAContentSigner(cryptService, slot, keyId, signatureAlgId);
                    }
                }
                else if(publicKey instanceof ECPublicKey)
                {
                    signer = new P11ECDSAContentSigner(cryptService, slot, keyId, signatureAlgId);
                }
                else
                {
                    throw new OperatorCreationException("Unsupported key " + publicKey.getClass().getName());
                }
                signers.add(signer);
            }
        } catch (NoSuchAlgorithmException e)
        {
            throw new OperatorCreationException("no such algorithm", e);
        }

        PrivateKey privateKey;
        try
        {
            privateKey = new P11PrivateKey(cryptService, slot, keyId);
        } catch (InvalidKeyException e)
        {
            throw new OperatorCreationException("Could not construct P11PrivateKey: " + e.getMessage(), e);
        }

        DefaultConcurrentContentSigner concurrentSigner = new DefaultConcurrentContentSigner(signers, privateKey);
        concurrentSigner.setCertificate(cert);

        return concurrentSigner;
    }
}
