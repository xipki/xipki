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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.SecurityUtil;
import org.xipki.common.ParamChecker;
import org.xipki.security.SignerUtil;
import org.xipki.security.SoftTokenContentSignerBuilder;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Identity;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class KeystoreP11Identity extends P11Identity
{
    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11Identity.class);

    private final String sha1sum;
    private final BlockingDeque<Cipher> rsaCiphers = new LinkedBlockingDeque<>();
    private final BlockingDeque<Signature> dsaSignatures = new LinkedBlockingDeque<>();

    public KeystoreP11Identity(
            String sha1sum,
            P11SlotIdentifier slotId,
            P11KeyIdentifier keyId,
            PrivateKey privateKey,
            X509Certificate[] certificateChain,
            int maxSessions)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        super(slotId, keyId, certificateChain, getPublicKeyOfFirstCert(certificateChain));
        ParamChecker.assertNotNull("privateKey", privateKey);
        ParamChecker.assertNotEmpty("sha1sum", sha1sum);

        if(certificateChain == null || certificateChain.length < 1 || certificateChain[0] == null)
        {
            throw new IllegalArgumentException("no certificate is specified");
        }

        this.sha1sum = sha1sum;
        if(this.publicKey instanceof RSAPublicKey)
        {
            String providerName;
            if(Security.getProvider(SoftTokenContentSignerBuilder.PROVIDER_XIPKI_NSS_CIPHER) != null)
            {
                providerName = SoftTokenContentSignerBuilder.PROVIDER_XIPKI_NSS_CIPHER;
            }
            else
            {
                providerName = "BC";
            }

            LOG.info("use provider {}", providerName);

            for(int i = 0; i < maxSessions; i++)
            {
                Cipher rsaCipher;
                try
                {
                    final String algo = "RSA/ECB/NoPadding";
                    rsaCipher = Cipher.getInstance(algo, providerName);
                    LOG.info("use cipher algorithm {}", algo);
                }catch(NoSuchPaddingException e)
                {
                    throw new NoSuchAlgorithmException("NoSuchPadding", e);
                }catch(NoSuchAlgorithmException e)
                {
                    final String algo = "RSA/NONE/NoPadding";
                    try
                    {
                        rsaCipher = Cipher.getInstance(algo, providerName);
                        LOG.info("use cipher algorithm {}", algo);
                    } catch (NoSuchPaddingException e1)
                    {
                        throw new NoSuchAlgorithmException("NoSuchPadding", e);
                    }
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
                algorithm = "NONEwithECDSA";
            }
            else if(this.publicKey instanceof DSAPublicKey)
            {
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

    private static PublicKey getPublicKeyOfFirstCert(X509Certificate[] certificateChain)
    {
        if(certificateChain == null || certificateChain.length < 1 || certificateChain[0] == null)
        {
            throw new IllegalArgumentException("no certificate is specified");
        }
        return certificateChain[0].getPublicKey();
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
        byte[] truncatedDigest = SecurityUtil.leftmost(hash, signatureKeyBitLength);
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
            return sig.sign();
        } catch (SignatureException e)
        {
            throw new SignerException("SignatureException: " + e.getMessage(), e);
        }finally
        {
            dsaSignatures.add(sig);
        }
    }

    public String getSha1Sum()
    {
        return sha1sum;
    }

}
