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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.BadAsn1ObjectException;

/**
 *
 * <pre>
 * SignTemplate ::= SEQUENCE {
 *     entityId       EntityIdentifier,
 *     mechanism      Mechanism,
 *     message        OCTET STRING
 *     }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class ASN1SignTemplate extends ASN1Object {

    private ASN1EntityIdentifier entityId;

    private ASN1Mechanism mechanism;

    private byte[] message;

    private ASN1SignTemplate(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        final int n = seq.size();
        if (n != 3) {
            StringBuilder sb = new StringBuilder(100);
            sb.append("wrong number of elements in sequence 'SignTemplate'");
            sb.append(", is '").append(n).append("'");
            sb.append(", but expected '3'");
            throw new BadAsn1ObjectException(sb.toString());
        }

        this.entityId = ASN1EntityIdentifier.getInstance(seq.getObjectAt(0));
        this.mechanism = ASN1Mechanism.getInstance(seq.getObjectAt(1));
        DEROctetString octetString = (DEROctetString) DEROctetString.getInstance(
                seq.getObjectAt(2));
        this.message = octetString.getOctets();
    }

    public ASN1SignTemplate(
            final ASN1EntityIdentifier entityId,
            final long mechanism,
            final ASN1P11Params parameter,
            final byte[] message) {
        this.entityId = ParamUtil.requireNonNull("entityId", entityId);
        this.message = ParamUtil.requireNonNull("message", message);
    }

    public static ASN1SignTemplate getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof ASN1SignTemplate) {
            return (ASN1SignTemplate) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new ASN1SignTemplate((ASN1Sequence) obj);
            }

            if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse encoded SignTemplate");
        }

        throw new BadAsn1ObjectException("unknown object in SignTemplate.getInstance(): "
                + obj.getClass().getName());
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(entityId.toASN1Primitive());
        vector.add(new DEROctetString(message));
        return new DERSequence(vector);
    }

    public byte[] getMessage() {
        return message;
    }

    public ASN1EntityIdentifier getEntityId() {
        return entityId;
    }

    public ASN1Mechanism getMechanism() {
        return mechanism;
    }
}
