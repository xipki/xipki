/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.security.api.p11.remote;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.commons.security.api.BadAsn1ObjectException;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 *
 * <pre>
 * SlotIdentifier ::= SEQUENCE {
 *     slotIndex         INTEGER OPTIONAL,
 *                       -- At least one of slotIndex and slotId must present.
 *     slotId        [1] EXPLICIT INTEGER OPTIONAL
 *     }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SlotIdentifier extends ASN1Object {

    private P11SlotIdentifier slotId;

    public SlotIdentifier(
            final P11SlotIdentifier slotId) {
        if (slotId == null) {
            throw new IllegalArgumentException("slotId could not be null");
        }

        this.slotId = slotId;
    }

    private SlotIdentifier(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        int size = seq.size();
        if (size < 1) {
            throw new BadAsn1ObjectException("wrong number of elements in sequence");
        }

        try {
            Integer slotIndex = null;

            ASN1Encodable slotIdASN1Obj = null;
            ASN1Encodable obj = seq.getObjectAt(0);
            if (obj instanceof ASN1Integer) {
                slotIndex = ((ASN1Integer) obj).getPositiveValue().intValue();
                if (size > 1) {
                    slotIdASN1Obj = seq.getObjectAt(1);
                }
            } else {
                slotIdASN1Obj = obj;
            }

            Long localSlotId = null;

            if (slotIdASN1Obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagObj = (ASN1TaggedObject) slotIdASN1Obj;

                int tagNo = tagObj.getTagNo();
                if (tagNo == 1) {
                    ASN1Integer i = ASN1Integer.getInstance(tagObj.getObject());
                    localSlotId = i.getPositiveValue().longValue();
                } else {
                    throw new BadAsn1ObjectException("unknown tag " + tagNo);
                }
            }

            this.slotId = new P11SlotIdentifier(slotIndex, localSlotId);
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(ex.getMessage(), ex);
        }
    } // constructor

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (slotId.getSlotIndex() != null) {
            vector.add(new ASN1Integer(slotId.getSlotIndex()));
        }

        if (slotId.getSlotId() != null) {
            DERTaggedObject taggedObj = new DERTaggedObject(true, 1,
                    new ASN1Integer(slotId.getSlotId()));
            vector.add(taggedObj);
        }

        return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
        return slotId;
    }

    public static SlotIdentifier getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof SlotIdentifier) {
            return (SlotIdentifier) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new SlotIdentifier((ASN1Sequence) obj);
            }

            if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse encoded SlotIdentifier");
        }

        throw new BadAsn1ObjectException("unknown object in SlotIdentifier.getInstance(): "
                + obj.getClass().getName());
    }

}
