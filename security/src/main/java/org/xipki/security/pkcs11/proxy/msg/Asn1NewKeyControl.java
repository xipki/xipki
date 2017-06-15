/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.security.pkcs11.proxy.msg;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11NewKeyControl;

/**
 * <pre>
 * NewKeyControl ::= SEQUENCE {
 *     extractable        [0] EXPLICIT BOOLEAN OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class Asn1NewKeyControl extends ASN1Object {

    private final P11NewKeyControl control;

    public Asn1NewKeyControl(P11NewKeyControl control) {
        this.control = ParamUtil.requireNonNull("control", control);
    }

    private Asn1NewKeyControl(final ASN1Sequence seq) throws BadAsn1ObjectException {
        control = new P11NewKeyControl();
        final int size = seq.size();
        for (int i = 0; i < size; i++) {
            ASN1Encodable obj = seq.getObjectAt(i);
            if (obj instanceof ASN1TaggedObject) {
                continue;
            }

            ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
            int tagNo = tagObj.getTagNo();
            if (tagNo == 0) {
                boolean bv = ((ASN1Boolean) tagObj.getObject()).isTrue();
                control.setExtractable(bv);
            }
        }
    }

    public static Asn1NewKeyControl getInstance(final Object obj) throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1NewKeyControl) {
            return (Asn1NewKeyControl) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1NewKeyControl((ASN1Sequence) obj);
            } else if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            } else {
                throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse object: " + ex.getMessage(), ex);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(0,
                ASN1Boolean.getInstance(control.isExtractable())));
        return new DERSequence(vector);
    }

    public P11NewKeyControl getControl() {
        return control;
    }

}
