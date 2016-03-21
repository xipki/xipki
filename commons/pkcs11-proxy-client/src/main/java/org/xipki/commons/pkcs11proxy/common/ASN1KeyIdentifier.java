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
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.BadAsn1ObjectException;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;

/**
 *
 * <pre>
 * SlotIdentifier ::= SEQUENCE {
 *     id        OCTET STRING,
 *     label     UTF8STRING
 *     }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class ASN1KeyIdentifier extends ASN1Object {

    private P11KeyIdentifier keyId;

    public ASN1KeyIdentifier(
            final P11KeyIdentifier keyId) {
        this.keyId = ParamUtil.requireNonNull("keyId", keyId);
    }

    private ASN1KeyIdentifier(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        int size = seq.size();
        try {
            ParamUtil.requireRange("seq.size()", size, 2, 2);
            byte[] id = DEROctetString.getInstance(seq.getObjectAt(0)).getOctets();
            String label = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
            this.keyId = new P11KeyIdentifier(id, label);
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(
                    "invalid object ASN1KeyIdentifier: " + ex.getMessage(), ex);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new DEROctetString(keyId.getId()));
        vec.add(new DERUTF8String(keyId.getLabel()));
        return new DERSequence(vec);
    }

    public P11KeyIdentifier getKeyId() {
        return keyId;
    }

    public static ASN1KeyIdentifier getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof ASN1KeyIdentifier) {
            return (ASN1KeyIdentifier) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new ASN1KeyIdentifier((ASN1Sequence) obj);
            }

            if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse encoded ASN1KeyIdentifier");
        }

        throw new BadAsn1ObjectException("unknown object in ASN1KeyIdentifier.getInstance(): "
                + obj.getClass().getName());
    }

}
