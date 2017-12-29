/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;

/**
 *
 * <pre>
 * DigestSecretKeyTemplate ::= SEQUENCE {
 *     entityId       EntityIdentifier,
 *     mechanism      Mechanism}
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1DigestSecretKeyTemplate extends ASN1Object {

    private final Asn1P11EntityIdentifier identityId;

    private final Asn1Mechanism mechanism;

    private Asn1DigestSecretKeyTemplate(ASN1Sequence seq) throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 2, 2);
        int idx = 0;
        this.identityId = Asn1P11EntityIdentifier.getInstance(seq.getObjectAt(idx++));
        this.mechanism = Asn1Mechanism.getInstance(seq.getObjectAt(idx++));
    }

    public Asn1DigestSecretKeyTemplate(Asn1P11EntityIdentifier identityId, long mechanism) {
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        this.mechanism = new Asn1Mechanism(mechanism, null);
    }

    public static Asn1DigestSecretKeyTemplate getInstance(Object obj)
            throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1DigestSecretKeyTemplate) {
            return (Asn1DigestSecretKeyTemplate) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1DigestSecretKeyTemplate((ASN1Sequence) obj);
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
        vector.add(identityId);
        vector.add(mechanism);
        return new DERSequence(vector);
    }

    public Asn1P11EntityIdentifier identityId() {
        return identityId;
    }

    public Asn1Mechanism mechanism() {
        return mechanism;
    }
}
