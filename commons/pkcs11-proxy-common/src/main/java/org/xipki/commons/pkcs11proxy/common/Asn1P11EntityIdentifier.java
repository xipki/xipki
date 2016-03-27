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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.BadAsn1ObjectException;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11ObjectIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 *
 * <pre>
 * EntityIdentifer ::= SEQUENCE {
 *     slotId     SlotIdentifier,
 *     keyId      KeyIdentifier
 *     }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1P11EntityIdentifier extends ASN1Object {

    private Asn1P11SlotIdentifier slotId;

    private Asn1P11ObjectIdentifier objectId;

    private P11EntityIdentifier entityId;

    public Asn1P11EntityIdentifier(
            final P11SlotIdentifier slotId,
            final P11ObjectIdentifier objectId) {
        ParamUtil.requireNonNull("slotId", slotId);
        ParamUtil.requireNonNull("objectId", objectId);
        init(null, new Asn1P11SlotIdentifier(slotId), new Asn1P11ObjectIdentifier(objectId));
    }

    public Asn1P11EntityIdentifier(
            final Asn1P11SlotIdentifier slotId,
            final Asn1P11ObjectIdentifier objectId) {
        ParamUtil.requireNonNull("slotId", slotId);
        ParamUtil.requireNonNull("objectId", objectId);
        init(null, slotId, objectId);
    }

    public Asn1P11EntityIdentifier(
            final P11EntityIdentifier entityId) {
        ParamUtil.requireNonNull("entityId", entityId);
        init(entityId, null, null);
    }

    private Asn1P11EntityIdentifier(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 2, 2);
        Asn1P11SlotIdentifier slotId = Asn1P11SlotIdentifier.getInstance(seq.getObjectAt(0));
        Asn1P11ObjectIdentifier objectId = Asn1P11ObjectIdentifier.getInstance(seq.getObjectAt(0));
        init(null, slotId, objectId);
    }

    public static Asn1P11EntityIdentifier getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1P11EntityIdentifier) {
            return (Asn1P11EntityIdentifier) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1P11EntityIdentifier((ASN1Sequence) obj);
            } else if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            } else {
                throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse encoded object");
        }
    }

    private void init(
            final P11EntityIdentifier entityId,
            final Asn1P11SlotIdentifier slotId,
            final Asn1P11ObjectIdentifier objectId) {
        if (entityId != null) {
            this.entityId = entityId;
            this.slotId = new Asn1P11SlotIdentifier(entityId.getSlotId());
            this.objectId = new Asn1P11ObjectIdentifier(entityId.getObjectId());
        } else {
            this.entityId = new P11EntityIdentifier(slotId.getSlotId(), objectId.getObjectId());
            this.slotId = ParamUtil.requireNonNull("slotId", slotId);
            this.objectId = ParamUtil.requireNonNull("keyId", objectId);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(slotId.toASN1Primitive());
        vector.add(objectId.toASN1Primitive());
        return new DERSequence(vector);
    }

    public Asn1P11SlotIdentifier getSlotId() {
        return slotId;
    }

    public Asn1P11ObjectIdentifier getObjectId() {
        return objectId;
    }

    public P11EntityIdentifier getEntityId() {
        return entityId;
    }

}
