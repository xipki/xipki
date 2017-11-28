/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11.proxy.msg;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.exception.BadAsn1ObjectException;

/**
 *
 * <pre>
 * Mechanism ::= SEQUENCE {
 *     mechanism     INTEGER,
 *     params        P11Params OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1Mechanism extends ASN1Object {

    private final long mechanism;

    private final Asn1P11Params params;

    public Asn1Mechanism(final long mechanism, final Asn1P11Params params) {
        this.mechanism = mechanism;
        this.params = params;
    }

    private Asn1Mechanism(final ASN1Sequence seq) throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 1, 2);
        int size = seq.size();
        int idx = 0;
        this.mechanism = Asn1Util.getInteger(seq.getObjectAt(idx++)).longValue();
        this.params = (size > 1)  ? Asn1P11Params.getInstance(seq.getObjectAt(idx++)) : null;
    }

    public static Asn1Mechanism getInstance(final Object obj) throws BadAsn1ObjectException {
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

    public long mechanism() {
        return mechanism;
    }

    public Asn1P11Params params() {
        return params;
    }

}
