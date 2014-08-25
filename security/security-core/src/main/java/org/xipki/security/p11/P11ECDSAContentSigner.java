/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11ECDSAContentSigner implements ContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(P11ECDSAContentSigner.class);

    private final AlgorithmIdentifier algorithmIdentifier;
    private final DigestOutputStream outputStream;

    private final P11CryptService cryptService;
    private final P11SlotIdentifier slot;
    private final P11KeyIdentifier keyId;

    public P11ECDSAContentSigner(
            P11CryptService cryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId,
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
        try
        {
            return cryptService.CKM_ECDSA(hashValue, slot, keyId);
        } catch (SignerException e)
        {
            LOG.warn("SignerException: {}", e.getMessage());
            LOG.debug("SignerException", e);
            throw new RuntimeCryptoException("SignerException: " + e.getMessage());
        } catch (Throwable t)
        {
            final String message = "Throwable";
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);
            throw new RuntimeCryptoException(t.getClass().getName() + ": " + t.getMessage());
        }
    }

}
