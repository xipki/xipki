/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.remotep11.common.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.security.api.PKCS11SlotIdentifier;

/**
 *
 * <pre>
 * SlotIdentifier ::= SEQUENCE {
 *     slotIndex   INTEGER OPTIONAL, -- At least one of slotIndex and slotId must present.
 *     slotId      [1] EXPLICIT INTEGER OPTIONAL
 * }
 * </pre>
 *
 */

public class SlotIdentifier extends ASN1Object
{
    private PKCS11SlotIdentifier slotId;

    public SlotIdentifier(PKCS11SlotIdentifier slotId)
    {
        if(slotId == null)
        {
            throw new IllegalArgumentException("slotId could not be null");
        }

        this.slotId = slotId;
    }

    private SlotIdentifier(ASN1Sequence seq)
    {
        int size = seq.size();
        if (size < 1)
        {
            throw new IllegalArgumentException("wrong number of elements in sequence");
        }

        Integer slotIndex = null;

        ASN1Encodable slotIdASN1Obj = null;
        ASN1Encodable obj = seq.getObjectAt(0);
        if(obj instanceof ASN1Integer)
        {
            slotIndex = ((ASN1Integer) obj).getPositiveValue().intValue();
            if(size > 1)
            {
                slotIdASN1Obj = seq.getObjectAt(1);
            }
        }
        else
        {
            slotIdASN1Obj = obj;
        }

        Long slotId = null;

        if (slotIdASN1Obj instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagObj = (ASN1TaggedObject) slotIdASN1Obj;

            int tagNo = tagObj.getTagNo();
            if(tagNo == 1)
            {
                ASN1Integer i = ASN1Integer.getInstance(tagObj.getObject());
                slotId = i.getPositiveValue().longValue();
            }
            else
            {
                throw new IllegalArgumentException("Unknown tag " + tagNo);
            }
        }

        this.slotId = new PKCS11SlotIdentifier(slotIndex, slotId);
    }

    public static SlotIdentifier getInstance(
            Object obj)
    {
        if (obj == null || obj instanceof SlotIdentifier)
        {
            return (SlotIdentifier)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new SlotIdentifier((ASN1Sequence) obj);
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
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        if(slotId.getSlotIndex() != null)
        {
            vector.add(new ASN1Integer(slotId.getSlotIndex()));
        }

        if(slotId.getSlotId() != null)
        {
            DERTaggedObject taggedObj = new DERTaggedObject(true, 1, new DERInteger(slotId.getSlotId()));
            vector.add(taggedObj);
        }

        return new DERSequence(vector);
    }

    public PKCS11SlotIdentifier getSlotId() {
        return slotId;
    }

}
