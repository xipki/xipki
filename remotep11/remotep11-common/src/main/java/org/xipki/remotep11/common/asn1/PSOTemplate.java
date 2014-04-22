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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 *
 * <pre>
 * PSOTemplate ::= SEQUENCE
 {
 *     slotAndKeyIdentifier   SlotAndKeyIdentifer
 *     message                OCTET STRING,
 * }
 * </pre>
 *
 */
public class PSOTemplate extends ASN1Object
{
    private SlotAndKeyIdentifer slotAndKeyIdentifier;
    private byte[] message;

    private PSOTemplate(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("wrong number of elements in sequence");
        }

        this.slotAndKeyIdentifier = SlotAndKeyIdentifer.getInstance(seq.getObjectAt(0));
        DEROctetString octetString = (DEROctetString) DEROctetString.getInstance(seq.getObjectAt(1));
        this.message = octetString.getOctets();
    }

    public PSOTemplate(SlotAndKeyIdentifer slotAndKeyIdentifier, byte[] message)
    {
        if(slotAndKeyIdentifier == null)
        {
            throw new IllegalArgumentException("slotAndKeyIdentifier could not be null");
        }
        if(message == null)
        {
            throw new IllegalArgumentException("message could not be null");
        }

        this.slotAndKeyIdentifier = slotAndKeyIdentifier;
        this.message = message;
    }

    public static PSOTemplate getInstance(
            Object obj)
    {
        if (obj == null || obj instanceof PSOTemplate)
        {
            return (PSOTemplate)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new PSOTemplate((ASN1Sequence) obj);
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
        vector.add(slotAndKeyIdentifier.toASN1Primitive());
        vector.add(new DEROctetString(message));
        return new DERSequence(vector);
    }

    public byte[] getMessage()
    {
        return message;
    }

    public SlotAndKeyIdentifer getSlotAndKeyIdentifer()
    {
        return slotAndKeyIdentifier;
    }
}
