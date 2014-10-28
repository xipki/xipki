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

package org.xipki.security.api.p11.remote;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 *
 * <pre>
 * SlotAndKeyIdentifer ::= SEQUENCE
 * {
 *     slotIdentifier   SlotIdentifier,
 *     keyIdentifier    KeyIdentifier,
 * }
 * </pre>
 *
 * @author Lijun Liao
 */

public class SlotAndKeyIdentifer extends ASN1Object
{
    private SlotIdentifier slotIdentifier;
    private KeyIdentifier keyIdentifier;

    public SlotAndKeyIdentifer(SlotIdentifier slotIdentifier,
            KeyIdentifier keyIdentifier)
    {
        if(slotIdentifier == null)
        {
            throw new IllegalArgumentException("slotIdentifier could not be null");
        }

        if(keyIdentifier == null)
        {
            throw new IllegalArgumentException("keyIdentifier could not be null");
        }

        this.slotIdentifier = slotIdentifier;
        this.keyIdentifier = keyIdentifier;
    }

    private SlotAndKeyIdentifer(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("wrong number of elements in sequence");
        }

        this.slotIdentifier = SlotIdentifier.getInstance(seq.getObjectAt(0));
        this.keyIdentifier = KeyIdentifier.getInstance(seq.getObjectAt(1));
    }

    public static SlotAndKeyIdentifer getInstance(
            Object obj)
    {
        if (obj == null || obj instanceof SlotAndKeyIdentifer)
        {
            return (SlotAndKeyIdentifer)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new SlotAndKeyIdentifer((ASN1Sequence) obj);
        }

        if (obj instanceof byte[])
        {
            try
            {
                return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("unable to parse encoded general name");
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(slotIdentifier.toASN1Primitive());
        vector.add(keyIdentifier.toASN1Primitive());
        return new DERSequence(vector);
    }

    public SlotIdentifier getSlotIdentifier()
    {
        return slotIdentifier;
    }

    public KeyIdentifier getKeyIdentifier()
    {
        return keyIdentifier;
    }

}
