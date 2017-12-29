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

package org.xipki.security;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;

/**
 *
 * <pre>
 * ExtensionExistence ::= SEQUENCE
 * {
 *     needExtensions [0] ExtensionTypes EXPLICIT OPTIONAL,
 *     wantExtensions [1] ExtensionTypes EXPLICIT OPTIONAL,
 * }
 *
 * ExtensionTypes ::= SEQUENCE OF OBJECT IDENTIFIER
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionExistence extends ASN1Object {

    private List<ASN1ObjectIdentifier> needExtensions;

    private List<ASN1ObjectIdentifier> wantExtensions;

    public ExtensionExistence(List<ASN1ObjectIdentifier> needExtensions,
            List<ASN1ObjectIdentifier> wantExtensions) {
        this.needExtensions = needExtensions;
        this.wantExtensions = wantExtensions;

        if (this.needExtensions == null) {
            List<ASN1ObjectIdentifier> list = Collections.emptyList();
            this.needExtensions = Collections.unmodifiableList(list);
        }

        if (this.wantExtensions == null) {
            List<ASN1ObjectIdentifier> list = Collections.emptyList();
            this.wantExtensions = Collections.unmodifiableList(list);
        }

    }

    private ExtensionExistence(ASN1Sequence seq) {
        int size = seq.size();
        if (size > 2) {
            throw new IllegalArgumentException("wrong number of elements in sequence");
        }

        for (int i = 0; i < size; i++) {
            ASN1TaggedObject tagObject = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            int tag = tagObject.getTagNo();
            ParamUtil.requireRange("tag", tag, 0, 1);
            ASN1Sequence subSeq = ASN1Sequence.getInstance(tagObject.getObject());
            List<ASN1ObjectIdentifier> oids = new LinkedList<>();
            int subSize = subSeq.size();
            for (int j = 0; j < subSize; j++) {
                oids.add(ASN1ObjectIdentifier.getInstance(subSeq.getObjectAt(j)));
            }

            if (tag == 0) {
                needExtensions = Collections.unmodifiableList(oids);
            } else {
                wantExtensions = Collections.unmodifiableList(oids);
            }
        }

        if (needExtensions == null) {
            List<ASN1ObjectIdentifier> list = Collections.emptyList();
            needExtensions = Collections.unmodifiableList(list);
        }

        if (wantExtensions == null) {
            List<ASN1ObjectIdentifier> list = Collections.emptyList();
            wantExtensions = Collections.unmodifiableList(list);
        }
    } // constructor

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (CollectionUtil.isNonEmpty(needExtensions)) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (ASN1ObjectIdentifier m : needExtensions) {
                vec.add(m);
            }
            vector.add(new DERTaggedObject(true, 0, new DERSequence(vec)));
        }

        if (CollectionUtil.isNonEmpty(wantExtensions)) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (ASN1ObjectIdentifier m : wantExtensions) {
                vec.add(m);
            }
            vector.add(new DERTaggedObject(true, 1, new DERSequence(vec)));
        }

        return new DERSequence(vector);
    }

    public List<ASN1ObjectIdentifier> needExtensions() {
        return needExtensions;
    }

    public List<ASN1ObjectIdentifier> wantExtensions() {
        return wantExtensions;
    }

    public static ExtensionExistence getInstance(Object obj) {
        if (obj == null || obj instanceof ExtensionExistence) {
            return (ExtensionExistence) obj;
        }

        if (obj instanceof ASN1Sequence) {
            return new ExtensionExistence((ASN1Sequence) obj);
        }

        if (obj instanceof byte[]) {
            try {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            } catch (IOException ex) {
                throw new IllegalArgumentException("unable to parse encoded general name");
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: "
                + obj.getClass().getName());
    }

}
