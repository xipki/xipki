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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.commons.security.api.exception.BadAsn1ObjectException;

/**
 *
 * <pre>
 * Mechanism ::= SEQUENCE {
 *     mechanism     INTEGER,
 *     params        P11Params OPTIONAL,
 *     }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1Mechanism extends ASN1Object {

    private final long mechanism;

    private final Asn1P11Params params;

    public Asn1Mechanism(
            final long mechanism,
            final Asn1P11Params params) {
        this.mechanism = mechanism;
        this.params = params;
    }

    private Asn1Mechanism(
            final ASN1Sequence seq)
    throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 1, 2);
        int size = seq.size();
        int idx = 0;
        this.mechanism = Asn1Util.getInteger(seq.getObjectAt(idx++)).longValue();
        if (size > 1) {
            this.params = Asn1P11Params.getInstance(seq.getObjectAt(idx++));
        } else {
            this.params = null;
        }
    }

    public static Asn1Mechanism getInstance(
            final Object obj)
    throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1Mechanism) {
            return (Asn1Mechanism) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1Mechanism((ASN1Sequence) obj);
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
        vector.add(new ASN1Integer(mechanism));
        if (params != null) {
            vector.add(params);
        }
        return new DERSequence(vector);
    }

    public long getMechanism() {
        return mechanism;
    }

    public Asn1P11Params getParams() {
        return params;
    }

}
