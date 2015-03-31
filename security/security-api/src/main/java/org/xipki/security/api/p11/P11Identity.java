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

package org.xipki.security.api.p11;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11Identity implements Comparable<P11Identity>
{
    protected final P11SlotIdentifier slotId;
    protected final P11KeyIdentifier keyId;

    protected final X509Certificate[] certificateChain;
    protected final PublicKey publicKey;
    private final int signatureKeyBitLength;

    public P11Identity(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId,
            final X509Certificate[] certificateChain,
            final PublicKey publicKey)
    {
        ParamChecker.assertNotNull("slotId", slotId);
        ParamChecker.assertNotNull("keyId", keyId);

        if((certificateChain == null || certificateChain.length < 1 || certificateChain[0] == null)
                && publicKey == null)
        {
            throw new IllegalArgumentException("neither certificate nor publicKey is non-null");
        }

        this.slotId = slotId;
        this.keyId = keyId;
        this.certificateChain = certificateChain;
        this.publicKey = publicKey == null ? certificateChain[0].getPublicKey() : publicKey;

        if(this.publicKey instanceof RSAPublicKey)
        {
            signatureKeyBitLength = ((RSAPublicKey) this.publicKey).getModulus().bitLength();
        }
        else if(this.publicKey instanceof ECPublicKey)
        {
            signatureKeyBitLength = ((ECPublicKey) this.publicKey).getParams().getCurve().getField().getFieldSize();
        }
        else if(this.publicKey instanceof DSAPublicKey)
        {
            signatureKeyBitLength = ((DSAPublicKey) this.publicKey).getParams().getQ().bitLength();
        }
        else
        {
            throw new IllegalArgumentException("currently only RSA, DSA and EC public key are supported, but not " +
                    this.publicKey.getAlgorithm() + " (class: " + this.publicKey.getClass().getName() + ")");
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
        return certificateChain == null ?
                null :
                java.util.Arrays.copyOf(certificateChain, certificateChain.length);
    }

    public PublicKey getPublicKey()
    {
        return publicKey == null ? certificateChain[0].getPublicKey() : publicKey;
    }

    public P11SlotIdentifier getSlotId()
    {
        return slotId;
    }

    public boolean match(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    {
        if(this.slotId.equals(slotId) == false)
        {
            return false;
        }

        return this.keyId.equals(keyId);
    }

    public boolean match(
            final P11SlotIdentifier slotId,
            final String keyLabel)
    {
        if(keyLabel == null)
        {
            return false;
        }

        return this.slotId.equals(slotId) && keyLabel.equals(keyId.getKeyLabel());
    }

    public int getSignatureKeyBitLength()
    {
        return signatureKeyBitLength;
    }

    @Override
    public int compareTo(P11Identity o)
    {
        return keyId.compareTo(o.keyId);
    }

}
