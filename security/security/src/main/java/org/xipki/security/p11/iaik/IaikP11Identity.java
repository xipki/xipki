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

package org.xipki.security.p11.iaik;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.xipki.common.util.SecurityUtil;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Identity;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

class IaikP11Identity extends P11Identity
{
    public IaikP11Identity(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId,
            final X509Certificate[] certificateChain,
            final PublicKey publicKey)
    {
        super(slotId, keyId, certificateChain, publicKey);
    }

    public byte[] CKM_RSA_PKCS(
            final IaikP11Module module,
            final byte[] encodedDigestInfo)
    throws SignerException
    {
        if(publicKey instanceof RSAPublicKey == false)
        {
            throw new SignerException("operation CKM_RSA_PKCS is not allowed for " +
                    publicKey.getAlgorithm() + " public key");
        }

        IaikP11Slot slot = module.getSlot(slotId);
        if(slot == null)
        {
            throw new SignerException("could not find slot " + slotId);
        }

        return slot.CKM_RSA_PKCS(encodedDigestInfo, keyId);
    }

    public byte[] CKM_RSA_X509(
            final IaikP11Module module,
            final byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof RSAPublicKey == false)
        {
            throw new SignerException("operation CKM_RSA_X509 is not allowed for " +
                    publicKey.getAlgorithm() + " public key");
        }

        IaikP11Slot slot = module.getSlot(slotId);
        if(slot == null)
        {
            throw new SignerException("could not find slot " + slotId);
        }

        return slot.CKM_RSA_X509(hash, keyId);
    }

    public byte[] CKM_ECDSA(
            final IaikP11Module module,
            final byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof ECPublicKey == false)
        {
            throw new SignerException("operation CKM_ECDSA is not allowed for " + publicKey.getAlgorithm() + " public key");
        }

        IaikP11Slot slot = module.getSlot(slotId);
        if(slot == null)
        {
            throw new SignerException("could not find slot " + slotId);
        }

        byte[] truncatedDigest = SecurityUtil.leftmost(hash, getSignatureKeyBitLength());

        return slot.CKM_ECDSA(truncatedDigest, keyId);
    }

    public byte[] CKM_DSA(
            final IaikP11Module module,
            final byte[] hash)
    throws SignerException
    {
        if(publicKey instanceof DSAPublicKey == false)
        {
            throw new SignerException("operation CKM_DSA is not allowed for " + publicKey.getAlgorithm() + " public key");
        }

        IaikP11Slot slot = module.getSlot(slotId);
        if(slot == null)
        {
            throw new SignerException("could not find slot " + slotId);
        }
        byte[] truncatedDigest = SecurityUtil.leftmost(hash, getSignatureKeyBitLength());
        return slot.CKM_DSA(truncatedDigest, keyId);
    }

}
