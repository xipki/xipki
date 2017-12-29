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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11ObjectIdentifier;

/**
 *
 * <pre>
 * P11ObjectIdentifier ::= SEQUENCE {
 *     id        OCTET STRING,
 *     label     UTF8STRING }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1P11ObjectIdentifier extends ASN1Object {

    private final P11ObjectIdentifier objectId;

    public Asn1P11ObjectIdentifier(P11ObjectIdentifier objectId) {
        this.objectId = ParamUtil.requireNonNull("objectId", objectId);
    }

    private Asn1P11ObjectIdentifier(ASN1Sequence seq) throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 2, 2);
        int idx = 0;
        byte[] id = Asn1Util.getOctetStringBytes(seq.getObjectAt(idx++));
        String label = Asn1Util.getUtf8String(seq.getObjectAt(idx++));
        this.objectId = new P11ObjectIdentifier(id, label);
    }

    public static Asn1P11ObjectIdentifier getInstance(Object obj) throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1P11ObjectIdentifier) {
            return (Asn1P11ObjectIdentifier) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1P11ObjectIdentifier((ASN1Sequence) obj);
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
        vec.add(new DEROctetString(objectId.id()));
        vec.add(new DERUTF8String(objectId.label()));
        return new DERSequence(vec);
    }

    public P11ObjectIdentifier objectId() {
        return objectId;
    }

}
