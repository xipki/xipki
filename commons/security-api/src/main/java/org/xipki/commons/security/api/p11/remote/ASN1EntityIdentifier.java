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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.BadAsn1ObjectException;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;

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

// CHECKSTYLE:SKIP
public class ASN1EntityIdentifier extends ASN1Object {

    private ASN1SlotIdentifier slotId;

    private ASN1KeyIdentifier keyId;

    private P11EntityIdentifier entityId;

    public ASN1EntityIdentifier(
            final ASN1SlotIdentifier slotId,
            final ASN1KeyIdentifier keyId) {
        ParamUtil.requireNonNull("slotId", slotId);
        ParamUtil.requireNonNull("keyId", keyId);
        init(null, slotId, keyId);
    }

    public ASN1EntityIdentifier(
            final P11EntityIdentifier entityId) {
        ParamUtil.requireNonNull("entityId", entityId);
        init(entityId, null, null);
    }

    private ASN1EntityIdentifier(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        final int n = seq.size();
        if (n != 2) {
            StringBuilder sb = new StringBuilder(100);
            sb.append("wrong number of elements in sequence 'SlotAndKeyIdentifier'");
            sb.append(", is '").append(n).append("'");
            sb.append(", but expected '").append(2).append("'");
            throw new BadAsn1ObjectException(sb.toString());
        }

        ASN1SlotIdentifier slotId = ASN1SlotIdentifier.getInstance(seq.getObjectAt(0));
        ASN1KeyIdentifier keyId = ASN1KeyIdentifier.getInstance(seq.getObjectAt(0));
        init(null, slotId, keyId);
    }

    private void init(
            final P11EntityIdentifier entityId,
            final ASN1SlotIdentifier slotId,
            final ASN1KeyIdentifier keyId) {
        if (entityId != null) {
            this.entityId = entityId;
            this.slotId = new ASN1SlotIdentifier(entityId.getSlotId());
            this.keyId = new ASN1KeyIdentifier(entityId.getKeyId());
        } else {
            this.entityId = new P11EntityIdentifier(slotId.getSlotId(), keyId.getKeyId());
            this.slotId = ParamUtil.requireNonNull("slotId", slotId);
            this.keyId = ParamUtil.requireNonNull("keyId", keyId);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(slotId.toASN1Primitive());
        vector.add(keyId.toASN1Primitive());
        return new DERSequence(vector);
    }

    public ASN1SlotIdentifier getSlotId() {
        return slotId;
    }

    public ASN1KeyIdentifier getKeyId() {
        return keyId;
    }

    public P11EntityIdentifier getEntityId() {
        return entityId;
    }

    public static ASN1EntityIdentifier getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof ASN1EntityIdentifier) {
            return (ASN1EntityIdentifier) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new ASN1EntityIdentifier((ASN1Sequence) obj);
            }

            if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse encoded SlotAndKeyIdentifier");
        }

        throw new BadAsn1ObjectException(
                "unknown object in SlotAndKeyIdentifier.getInstance(): "
                + obj.getClass().getName());
    }

}
