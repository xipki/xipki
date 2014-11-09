/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.security.p11.keystore;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.common.IoCertUtil;
import org.xipki.common.ParamChecker;
import org.xipki.security.SignerUtil;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class KeystoreP11Identity implements Comparable<KeystoreP11Identity>
{
    private final P11SlotIdentifier slotId;
    private final P11KeyIdentifier keyId;

    private final X509Certificate[] certificateChain;
    private final PublicKey publicKey;
    private final int signatureKeyBitLength;

    private final BlockingDeque<Cipher> rsaCiphers = new LinkedBlockingDeque<>();
    private final BlockingDeque<Signature> dsaSignatures = new LinkedBlockingDeque<>();

    public KeystoreP11Identity(
            P11SlotIdentifier slotId,
            P11KeyIdentifier keyId,
            PrivateKey privateKey,
            X509Certificate[] certificateChain,
            int maxSessions)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        ParamChecker.assertNotNull("slotId", slotId);
        ParamChecker.assertNotNull("keyId", keyId);

        if(certificateChain == null || certificateChain.length < 1 || certificateChain[0] == null)
        {
            throw new IllegalArgumentException("no certificate is specified");
        }

        this.slotId = slotId;
        this.keyId = keyId;
        this.certificateChain = certificateChain;
        this.publicKey = certificateChain[0].getPublicKey();

        if(this.publicKey instanceof RSAPublicKey)
        {
            signatureKeyBitLength = ((RSAPublicKey) this.publicKey).getModulus().bitLength();

            for(int i = 0; i < maxSessions; i++)
            {
                Cipher rsaCipher;
                try
                {
                    rsaCipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
                }catch(NoSuchPaddingException e)
                {
                    throw new NoSuchAlgorithmException("NoSuchPadding", e);
                }
                rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
                rsaCiphers.add(rsaCipher);
            }
        }
        else
        {
            String algorithm;
            if(this.publicKey instanceof ECPublicKey)
            {
                signatureKeyBitLength = ((ECPublicKey) this.publicKey).getParams().getCurve().getField().getFieldSize();
                algorithm = "NONEwithECDSA";
            }
            else if(this.publicKey instanceof DSAPublicKey)
            {
                signatureKeyBitLength = ((DSAPublicKey) this.publicKey).getParams().getQ().bitLength();
                algorithm = "NONEwithDSA";
            }
            else
            {
                throw new IllegalArgumentException("Currently only RSA, DSA and EC public key are supported, but not " +
                        this.publicKey.getAlgorithm() + " (class: " + this.publicKey.getClass().getName() + ")");
            }

            for(int i = 0; i < maxSessions; i++)
            {
                Signature dsaSignature = Signature.getInstance(algorithm, "BC");
                dsaSignature.initSign(privateKey);
                dsaSignatures.add(dsaSignature);
            }
        }
    }

    public P11KeyIdentifier getKeyId()
    {
        return keyId;
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

    public boolean match(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    {
        if(this.slotId.equals(slotId) == false)
        {
            return false;
        }

        return this.keyId.equals(keyId);
    }

    public boolean match(P11SlotIdentifier slotId, String keyLabel)
    {
        if(keyLabel == null)
        {
            return false;
        }

        return this.slotId.equals(slotId) && keyLabel.equals(keyId.getKeyLabel());
    }

    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo)
    throws SignerException
    {
        if(publicKey instanceof RSAPublicKey == false)
        {
            throw new SignerException("Operation CKM_RSA_PKCS is not allowed for " +
                    publicKey.getAlgorithm() + " public key");
        }

        byte[] padded = SignerUtil.pkcs1padding(encodedDigestInfo, (signatureKeyBitLength + 7)/8);
        return do_rsa_sign(padded);
    }

    public byte[] CKM_RSA_X509(byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof RSAPublicKey == false)
        {
            throw new SignerException("Operation CKM_RSA_X509 is not allowed for " +
                    publicKey.getAlgorithm() + " public key");
        }
        return do_rsa_sign(hash);
    }

    private byte[] do_rsa_sign(byte[] paddedHash)
    throws SignerException
    {
        Cipher cipher;
        try
        {
            cipher = rsaCiphers.takeFirst();
        } catch (InterruptedException e)
        {
            throw new SignerException("InterruptedException occurs while retrieving idle signature");
        }

        try
        {
            return cipher.doFinal(paddedHash);
        } catch (BadPaddingException | IllegalBlockSizeException e)
        {
            throw new SignerException("SignatureException: " + e.getMessage(), e);
        }finally
        {
            rsaCiphers.add(cipher);
        }
    }

    public byte[] CKM_ECDSA(byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof ECPublicKey == false)
        {
            throw new SignerException("Operation CKM_ECDSA is not allowed for " + publicKey.getAlgorithm() + " public key");
        }

        return do_dsa_sign(hash);
    }

    public byte[] CKM_DSA(byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof DSAPublicKey == false)
        {
            throw new SignerException("Operation CKM_DSA is not allowed for " + publicKey.getAlgorithm() + " public key");
        }
        return do_dsa_sign(hash);
    }

    private byte[] do_dsa_sign(byte[] hash)
    throws SignerException
    {
        byte[] truncatedDigest = IoCertUtil.leftmost(hash, signatureKeyBitLength);
        Signature sig;
        try
        {
            sig = dsaSignatures.takeFirst();
        } catch (InterruptedException e)
        {
            throw new SignerException("InterruptedException occurs while retrieving idle signature");
        }

        try
        {
            sig.update(truncatedDigest);
            byte[] signature = sig.sign();
            return convertToX962Signature(signature);
        } catch (SignatureException e)
        {
            throw new SignerException("SignatureException: " + e.getMessage(), e);
        }finally
        {
            dsaSignatures.add(sig);
        }
    }

    private static byte[] convertToX962Signature(byte[] signature)
    throws SignerException
    {
        byte[] ba = new byte[signature.length/2];
        ASN1EncodableVector sigder = new ASN1EncodableVector();

        System.arraycopy(signature, 0, ba, 0, ba.length);
        sigder.add(new ASN1Integer(new BigInteger(1, ba)));

        System.arraycopy(signature, ba.length, ba, 0, ba.length);
        sigder.add(new ASN1Integer(new BigInteger(1, ba)));

        DERSequence seq = new DERSequence(sigder);
        try
        {
            return seq.getEncoded();
        } catch (IOException e)
        {
            throw new SignerException("IOException, message: " + e.getMessage(), e);
        }
    }

    @Override
    public int compareTo(KeystoreP11Identity o)
    {
        return keyId.compareTo(o.keyId);
    }

}
