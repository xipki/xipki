/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.commons.pkcs11proxy.common;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.Arrays;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.exception.BadAsn1ObjectException;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 *
 * <pre>
 * RemoveObjectsParams ::= SEQUENCE {
 *     slotId     SlotIdentifier,
 *     id         OCTET STRING OPTIONAL, -- at least one of id and label must be present
 *     label      UTF8String OPTIONAL
 *     }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1RemoveObjectsParams extends ASN1Object {

    private final Asn1P11SlotIdentifier slotId;

    private final byte[] objectId;

    private final String objectLabel;

    public Asn1RemoveObjectsParams(
            final P11SlotIdentifier slotId,
            final byte[] objectId,
            final String objectLabel) {
        ParamUtil.requireNonNull("slotId", slotId);
        if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
            throw new IllegalArgumentException(
                    "at least onf of objectId and objectLabel must not be null");
        }

        this.objectId = objectId;
        this.objectLabel = objectLabel;
        this.slotId = new Asn1P11SlotIdentifier(slotId);
    }

    private Asn1RemoveObjectsParams(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 2, 3);
        int idx = 0;
        slotId = Asn1P11SlotIdentifier.getInstance(seq.getObjectAt(idx++));
        final int size = seq.size();
        ASN1Encodable asn1Id = null;
        ASN1Encodable asn1Label = null;
        if (size == 2) {
            ASN1Encodable asn1 = seq.getObjectAt(1);
            if (asn1 instanceof ASN1String) {
                asn1Label = asn1;
                asn1Id = null;
            } else {
                asn1Label = null;
                asn1Id = asn1;
            }
        } else {
            asn1Id = seq.getObjectAt(idx++);
            asn1Label = seq.getObjectAt(idx++);
        }

        objectId = (asn1Id == null)
                ? null
                : Asn1Util.getOctetStringBytes(asn1Id);

        objectLabel = (asn1Label == null)
                ? null
                : Asn1Util.getUtf8String(seq.getObjectAt(idx++));

        if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
            throw new BadAsn1ObjectException("invalid object Asn1RemoveObjectsParams: "
                    + "at least one of id and label must not be null");
        }
    }

    public static Asn1RemoveObjectsParams getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1RemoveObjectsParams) {
            return (Asn1RemoveObjectsParams) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1RemoveObjectsParams((ASN1Sequence) obj);
            } else if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            } else {
                throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(),
                    ex);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(slotId);
        vector.add(new DERUTF8String(objectLabel));
        return new DERSequence(vector);
    }

    public Asn1P11SlotIdentifier getSlotId() {
        return slotId;
    }

    public byte[] getObjectId() {
        return Arrays.clone(objectId);
    }

    public String getObjectLabel() {
        return objectLabel;
    }

}
