/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.security.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.xipki.common.util.ParamUtil;
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

    public P11PrivateKey(
            final P11CryptService p11CryptService,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws InvalidKeyException
    {
        ParamUtil.assertNotNull("p11CryptService", p11CryptService);
        ParamUtil.assertNotNull("slotId", slotId);
        ParamUtil.assertNotNull("keyId", keyId);

        this.p11CryptService = p11CryptService;
        this.slotId = slotId;
        this.keyId = keyId;
        PublicKey publicKey;
        try
        {
            publicKey = p11CryptService.getPublicKey(slotId, keyId);
        } catch (SignerException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }

        if (publicKey instanceof RSAPublicKey)
        {
            algorithm = "RSA";
            keysize = ((RSAPublicKey) publicKey).getModulus().bitLength();
        }
        else if (publicKey instanceof DSAPublicKey)
        {
            algorithm = "DSA";
            keysize = ((DSAPublicKey) publicKey).getParams().getP().bitLength();
        }
        else if (publicKey instanceof ECPublicKey)
        {
            algorithm = "EC";
            keysize = ((ECPublicKey) publicKey).getParams().getCurve().getField().getFieldSize();
        }
        else
        {
            throw new InvalidKeyException("unknown public key: " + publicKey);
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

    public byte[] CKM_RSA_PKCS(
            final byte[] encodedDigestInfo)
    throws SignatureException
    {
        if ("RSA".equals(algorithm) == false)
        {
            throw new SignatureException("could not compute RSA signature with " + algorithm
                    + " key");
        }

        try
        {
            return p11CryptService.CKM_RSA_PKCS(encodedDigestInfo, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_RSA_X509(
            final byte[] hash)
    throws SignatureException
    {
        if ("RSA".equals(algorithm) == false)
        {
            throw new SignatureException("could not compute RSA signature with " + algorithm
                    + " key");
        }

        try
        {
            return p11CryptService.CKM_RSA_X509(hash, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_ECDSA_X962(
            final byte[] hash)
    throws SignatureException
    {
        if ("EC".equals(algorithm) == false)
        {
            throw new SignatureException("could not compute ECDSA signature with " + algorithm
                    + " key");
        }

        try
        {
            return p11CryptService.CKM_ECDSA_X962(hash, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_ECDSA_Plain(
            final byte[] hash)
    throws SignatureException
    {
        if ("EC".equals(algorithm) == false)
        {
            throw new SignatureException("could not compute ECDSA signature with " + algorithm
                    + " key");
        }

        try
        {
            return p11CryptService.CKM_ECDSA_Plain(hash, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_DSA_X962(
            final byte[] hash)
    throws SignatureException
    {
        if ("DSA".equals(algorithm) == false)
        {
            throw new SignatureException("could not compute DSA signature with " + algorithm
                    + " key");
        }

        try
        {
            return p11CryptService.CKM_DSA_X962(hash, slotId, keyId);
        } catch (SignerException e)
        {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_DSA_Plain(
            final byte[] hash)
    throws SignatureException
    {
        if ("DSA".equals(algorithm) == false)
        {
            throw new SignatureException("could not compute DSA signature with " + algorithm
                    + " key");
        }

        try
        {
            return p11CryptService.CKM_DSA_Plain(hash, slotId, keyId);
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
