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
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.BadAsn1ObjectException;

/**
 *
 * <pre>
 * GenRSAKeypairParams ::= SEQUENCE {
 *     slotId               P11SlotIdentifier
 *     label                UTF8STRING,
 *     keysize              INTEGER,
 *     publicExponent       INTEGER OPTIONAL}
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class Asn1GenRSAKeypairParams extends ASN1Object {

    private final Asn1P11SlotIdentifier slotId;

    private final String label;

    private final int keysize;

    private final BigInteger publicExponent;

    public Asn1GenRSAKeypairParams(
            final Asn1P11SlotIdentifier slotId,
            final String label,
            final int keysize,
            final BigInteger publicExponent) {
        this.slotId = ParamUtil.requireNonNull("slotId", slotId);
        this.label = ParamUtil.requireNonBlank("label", label);
        this.keysize = ParamUtil.requireMin("keysize", keysize, 1);
        this.publicExponent = publicExponent;
    }

    private Asn1GenRSAKeypairParams(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 3, 4);
        final int size = seq.size();
        int idx = 0;
        slotId = Asn1P11SlotIdentifier.getInstance(seq.getObjectAt(idx++));
        label = Asn1Util.getUtf8String(seq.getObjectAt(idx++));
        ParamUtil.requireNonBlank("label", label);

        keysize = Asn1Util.getInteger(seq.getObjectAt(idx++)).intValue();
        ParamUtil.requireMin("keysize", keysize, 1);

        if (size > 3) {
            publicExponent = Asn1Util.getInteger(seq.getObjectAt(idx++));
        } else {
            publicExponent = null;
        }
    }

    public static Asn1GenRSAKeypairParams getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1GenRSAKeypairParams) {
            return (Asn1GenRSAKeypairParams) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1GenRSAKeypairParams((ASN1Sequence) obj);
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
        vector.add(new DERUTF8String(label));
        vector.add(new ASN1Integer(keysize));
        if (publicExponent != null) {
            vector.add(new ASN1Integer(publicExponent));
        }
        return new DERSequence(vector);
    }

    public Asn1P11SlotIdentifier getSlotId() {
        return slotId;
    }

    public String getLabel() {
        return label;
    }

    public int getKeysize() {
        return keysize;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

}
