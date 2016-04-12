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
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.exception.BadAsn1ObjectException;

/**
 *
 * <pre>
 * P11ObjectIdentifiers ::= SEQUENCE OF P11ObjectIdentifier
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1P11ObjectIdentifiers extends ASN1Object {

    private final List<Asn1P11ObjectIdentifier> objectIds;

    public Asn1P11ObjectIdentifiers(
            final List<Asn1P11ObjectIdentifier> objectIds) {
        this.objectIds = ParamUtil.requireNonNull("objectIds", objectIds);
    }

    private Asn1P11ObjectIdentifiers(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        this.objectIds = new LinkedList<>();
        final int size = seq.size();
        for (int i = 0; i < size; i++) {
            objectIds.add(Asn1P11ObjectIdentifier.getInstance(seq.getObjectAt(i)));
        }
    }

    public static Asn1P11ObjectIdentifiers getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1P11ObjectIdentifiers) {
            return (Asn1P11ObjectIdentifiers) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1P11ObjectIdentifiers((ASN1Sequence) obj);
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
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (Asn1P11ObjectIdentifier objectId : objectIds) {
            vec.add(objectId);
        }
        return new DERSequence(vec);
    }

    public List<Asn1P11ObjectIdentifier> getObjectIds() {
        return objectIds;
    }

}
