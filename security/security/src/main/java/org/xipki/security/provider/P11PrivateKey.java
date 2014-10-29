/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.xipki.common.ParamChecker;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class P11PrivateKey implements PrivateKey
{

    private static final long serialVersionUID = 1L;

    private final P11CryptService p11CryptService;
    private final P11SlotIdentifier slotId;
    private final P11KeyIdentifier keyId;
    private final String algorithm;
    private final int keysize;

    public P11PrivateKey(P11CryptService p11CryptService, P11SlotIdentifier slotId,
            P11KeyIdentifier keyId)
    throws InvalidKeyException
    {
        ParamChecker.assertNotNull("p11CryptService", p11CryptService);
        ParamChecker.assertNotNull("slotId", slotId);
        ParamChecker.assertNotNull("keyId", keyId);

        this.p11CryptService = p11CryptService;
        this.slotId = slotId;
        this.keyId = keyId;
        PublicKey publicKey;
        try
        {
            publicKey = p11CryptService.getPublicKey(slotId, keyId);
        } catch (SignerException e)
        {
            throw new InvalidKeyException(e);
        }

        if(publicKey instanceof RSAPublicKey)
        {
            algorithm = "RSA";
            keysize = ((RSAPublicKey) publicKey).getModulus().bitLength();
        }
        else if(publicKey instanceof DSAPublicKey)
        {
            algorithm = "DSA";
            keysize = ((DSAPublicKey) publicKey).getParams().getP().bitLength();
        }
        else if(publicKey instanceof ECPublicKey)
        {
            algorithm = "EC";
            keysize = ((ECPublicKey) publicKey).getParams().getCurve().getField().getFieldSize();
        }
        else
        {
            throw new InvalidKeyException("Unknown public key: " + publicKey);
        }
    }

    @Override
    public String getFormat()
    {
        return null;
    }

    @Override
    public byte[] getEncoded()
    {
        return null;
    }

    @Override
    public String getAlgorithm()
    {
        return algorithm;
    }

    public int getKeysize()
    {
        return keysize;
    }

    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo)
    throws SignatureException
    {
        if("RSA".equals(algorithm) == false)
        {
            throw new SignatureException("Could not compute RSA signature with " + algorithm + " key");
        }

        try
        {
            return p11CryptService.CKM_RSA_PKCS(encodedDigestInfo, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_RSA_X509(byte[] hash)
    throws SignatureException
    {
        if("RSA".equals(algorithm) == false)
        {
            throw new SignatureException("Could not compute RSA signature with " + algorithm + " key");
        }

        try
        {
            return p11CryptService.CKM_RSA_X509(hash, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_ECDSA(byte[] hash)
    throws SignatureException
    {
        if("EC".equals(algorithm) == false)
        {
            throw new SignatureException("Could not compute ECDSA signature with " + algorithm + " key");
        }

        try
        {
            return p11CryptService.CKM_ECDSA(hash, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_DSA(byte[] hash)
    throws SignatureException
    {
        if("DSA".equals(algorithm) == false)
        {
            throw new SignatureException("Could not compute DSA signature with " + algorithm + " key");
        }

        try
        {
            return p11CryptService.CKM_DSA(hash, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    P11CryptService getP11CryptService()
    {
        return p11CryptService;
    }

    P11SlotIdentifier getSlotId()
    {
        return slotId;
    }

    P11KeyIdentifier getKeyId()
    {
        return keyId;
    }

}
