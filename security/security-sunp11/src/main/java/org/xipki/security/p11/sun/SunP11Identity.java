/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.sun;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class SunP11Identity implements Comparable<SunP11Identity>
{
    private final Cipher rsaCipher;
    private final Signature ecdsaSignature;
    private final P11SlotIdentifier slotId;

    private final String keyLabel;
    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;
    private final PublicKey publicKey;
    private final int signatureKeyBitLength;

    public SunP11Identity(
            Provider p11Provider,
            P11SlotIdentifier slotId,
            String keyLabel,
            PrivateKey privateKey,
            X509Certificate[] certificateChain,
            PublicKey publicKey)
    throws SignerException
    {
        super();

        ParamChecker.assertNotNull("p11Provider", p11Provider);
        ParamChecker.assertNotNull("slotId", slotId);
        ParamChecker.assertNotNull("privateKey", privateKey);
        ParamChecker.assertNotNull("keyLabel", keyLabel);

        if((certificateChain == null || certificateChain.length == 0 || certificateChain[0] == null)
                && publicKey == null)
        {
            throw new IllegalArgumentException("Neither certificate nor publicKey is non-null");
        }

        this.slotId = slotId;
        this.privateKey = privateKey;
        this.publicKey = publicKey == null ? certificateChain[0].getPublicKey() : publicKey;
        this.certificateChain = certificateChain;

        this.keyLabel = keyLabel;

        if(this.publicKey instanceof RSAPublicKey)
        {
            signatureKeyBitLength = ((RSAPublicKey) this.publicKey).getModulus().bitLength();
            String algorithm = "RSA/ECB/NoPadding";
            this.ecdsaSignature = null;
            try
            {
                this.rsaCipher = Cipher.getInstance(algorithm, p11Provider);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e)
            {
                throw new SignerException(e.getClass().getName() + ": " + e.getMessage(), e);
            }
            try
            {
                this.rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            } catch (InvalidKeyException e)
            {
                throw new SignerException("InvalidKeyException: " + e.getMessage(), e);
            }
        }
        else if(this.publicKey instanceof ECPublicKey)
        {
            signatureKeyBitLength = ((ECPublicKey) this.publicKey).getParams().getCurve().getField().getFieldSize();
            String algorithm = "NONEwithECDSA";
            try
            {
                this.ecdsaSignature = Signature.getInstance(algorithm, p11Provider);
            } catch (NoSuchAlgorithmException e)
            {
                throw new SignerException("NoSuchAlgorithmException: " + e.getMessage(), e);
            }
            try
            {
                this.ecdsaSignature.initSign(privateKey);
            } catch (InvalidKeyException e)
            {
                throw new SignerException("InvalidKeyException: " + e.getMessage(), e);
            }
            this.rsaCipher = null;
        }
        else
        {
            throw new IllegalArgumentException("Currently only RSA and EC public key are supported, but not " +
                    this.publicKey.getAlgorithm() + " (class: " + this.publicKey.getClass().getName() + ")");
        }
    }

    public String getKeyLabel()
    {
        return keyLabel;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public X509Certificate getCertificate()
    {
        return (certificateChain != null && certificateChain.length > 0) ? certificateChain[0] : null;
    }

    public X509Certificate[] getCertificateChain()
    {
        return certificateChain;
    }

    public PublicKey getPublicKey()
    {
        return publicKey == null ? certificateChain[0].getPublicKey() : publicKey;
    }

    public P11SlotIdentifier getSlotId()
    {
        return slotId;
    }

    public boolean match(P11SlotIdentifier slotId, String keyLabel)
    {
        return this.slotId.equals(slotId) && this.keyLabel.equals(keyLabel);
    }

    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo)
    throws SignerException
    {
        byte[] padded = pkcs1padding(encodedDigestInfo, (signatureKeyBitLength + 7)/8);
        return CKM_RSA_X_509(padded);
    }

    private static byte[] pkcs1padding(byte[] in, int blockSize)
    throws SignerException
    {
        int inLen = in.length;

        if (inLen+3 > blockSize)
        {
            throw new SignerException("data too long (maximal " + (blockSize - 3) + " allowed): " + inLen);
        }

        byte[]  block = new byte[blockSize];

        block[0] = 0x00;
        block[1] = 0x01;                        // type code 1

        for (int i = 2; i != block.length - inLen - 1; i++)
        {
            block[i] = (byte)0xFF;
        }

        block[block.length - inLen - 1] = 0x00;       // mark the end of the padding
        System.arraycopy(in, 0, block, block.length - inLen, inLen);
        return block;
    }

    public byte[] CKM_RSA_X_509(byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof RSAPublicKey == false)
        {
            throw new SignerException("Operation CKM_RSA_X_509 is not allowed for " + publicKey.getAlgorithm() + " public key");
        }

        synchronized (rsaCipher)
        {
            try
            {
                rsaCipher.update(hash);
                return rsaCipher.doFinal();
            } catch (IllegalBlockSizeException | BadPaddingException e)
            {
                throw new SignerException(e.getClass().getName() + ": " + e.getMessage(), e);
            }
        }
    }

    public byte[] CKM_ECDSA(byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof ECPublicKey == false)
        {
            throw new SignerException("Operation CKM_ECDSA is not allowed for " + publicKey.getAlgorithm() + " public key");
        }

        byte[] truncatedDigest = IoCertUtil.leftmost(hash, signatureKeyBitLength);

        synchronized (ecdsaSignature)
        {
            try
            {
                ecdsaSignature.update(truncatedDigest);
                return ecdsaSignature.sign();
            } catch (SignatureException e)
            {
                throw new SignerException(e.getMessage(), e);
            }
        }
    }

    @Override
    public int compareTo(SunP11Identity o)
    {
        return this.keyLabel.compareTo(o.keyLabel);
    }
}
