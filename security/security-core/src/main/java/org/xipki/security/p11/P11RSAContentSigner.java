/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
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
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11RSAContentSigner implements ContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(P11RSAContentSigner.class);
    private final AlgorithmIdentifier algorithmIdentifier;
    private final DigestOutputStream outputStream;

    private final P11CryptService cryptService;
    private final PKCS11SlotIdentifier slot;
    private final Pkcs11KeyIdentifier keyId;

    private final AlgorithmIdentifier digAlgId;

    public P11RSAContentSigner(
            P11CryptService cryptService,
            PKCS11SlotIdentifier slot,
            Pkcs11KeyIdentifier keyId,
            AlgorithmIdentifier signatureAlgId)
    throws NoSuchAlgorithmException, NoSuchPaddingException, OperatorCreationException
    {
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("keyId", keyId);
        ParamChecker.assertNotNull("signatureAlgId", signatureAlgId);

        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm()))
        {
            throw new IllegalArgumentException("Unsupported signature algorithm " + signatureAlgId.getAlgorithm());
        }

        this.slot = slot;
        this.algorithmIdentifier = signatureAlgId;
        this.keyId = keyId;

        this.digAlgId = SignerUtil.extractDigesetAlgorithmIdentifier(signatureAlgId);
        Digest digest = BcDefaultDigestProvider.INSTANCE.get(digAlgId);

        this.cryptService = cryptService;
        this.outputStream = new DigestOutputStream(digest);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream()
    {
        outputStream.reset();
        return outputStream;
    }

    @Override
    public byte[] getSignature()
    {
        byte[] hashValue = outputStream.digest();
        DigestInfo digestInfo = new DigestInfo(digAlgId, hashValue);
        byte[] encodedDigestInfo;

        try
        {
            encodedDigestInfo = digestInfo.getEncoded();
        } catch (IOException e)
        {
            LOG.warn("IOException: {}", e.getMessage());
            LOG.debug("IOException", e);
            throw new RuntimeCryptoException("IOException: " + e.getMessage());
        }

        try
        {
            return cryptService.CKM_RSA_PKCS(encodedDigestInfo, slot, keyId);
        } catch (SignerException e)
        {
            LogUtil.logWarnThrowable(LOG, "SignerException", e);
            throw new RuntimeCryptoException("SignerException: " + e.getMessage());
        }
    }
}
