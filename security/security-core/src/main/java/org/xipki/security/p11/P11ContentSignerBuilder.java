/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.DefaultConcurrentContentSigner;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;
import org.xipki.security.provider.P11PrivateKey;

/**
 * @author Lijun Liao
 */

public class P11ContentSignerBuilder
{
    private final X509Certificate[] certificateChain;

    private final P11CryptService cryptService;
    private final P11SlotIdentifier slot;
    private final P11KeyIdentifier keyId;

    public P11ContentSignerBuilder(
            P11CryptService cryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId,
            X509Certificate[] certificateChain)
    throws SignerException
    {
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("keyId", keyId);

        X509Certificate signerCertInP11 = cryptService.getCertificate(slot, keyId);
        boolean keyExists = (signerCertInP11 != null);
        if(keyExists == false)
        {
            keyExists = (cryptService.getPublicKey(slot, keyId) != null);
        }

        if(keyExists == false)
        {
            throw new SignerException("Key with " + keyId + " does not exist");
        }

        this.cryptService = cryptService;
        this.keyId = keyId;
        this.slot = slot;

        Set<Certificate> caCerts = new HashSet<>();

        X509Certificate cert;
        int n = certificateChain == null ? 0 : certificateChain.length;
        if(n > 0)
        {
            cert = certificateChain[0];
            if(n > 1)
            {
                for(int i = 1; i < n; i++)
                {
                    caCerts.add(certificateChain[i]);
                }
            }
        }
        else
        {
            cert = signerCertInP11;
        }

        Certificate[] certsInKeystore = cryptService.getCertificates(slot, keyId);
        if(certsInKeystore.length > 1)
        {
            for(int i = 1; i < certsInKeystore.length; i++)
            {
                caCerts.add(certsInKeystore[i]);
            }
        }

        this.certificateChain = IoCertUtil.buildCertPath(cert, caCerts);
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

        List<ContentSigner> signers = new ArrayList<>(parallelism);

        PublicKey publicKey = certificateChain[0].getPublicKey();
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
                else if(publicKey instanceof DSAPublicKey)
                {
                    signer = new P11DSAContentSigner(cryptService, slot, keyId, signatureAlgId);
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
        concurrentSigner.setCertificateChain(certificateChain);

        return concurrentSigner;
    }
}
