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

package org.xipki.ocsp.server.impl.type;

import org.xipki.common.ASN1Type;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class TaggedCertSequence extends ASN1Type {

    private final byte[] encoded;

    private final int encodedLen;

    public TaggedCertSequence(byte[] encodedCert) {
        this(new byte[][]{encodedCert});
    }

    public TaggedCertSequence(byte[][] encodedCerts) {
        int seqBodyLen = 0;
        for (int i = 0; i < encodedCerts.length; i++) {
            seqBodyLen += encodedCerts[i].length;
        }

        int seqLen= getLen(seqBodyLen);
        encodedLen = getLen(seqLen);

        this.encoded = new byte[encodedLen];
        int idx = 0;
        idx += writeHeader((byte) 0xa0, seqLen, encoded, idx);
        idx += writeHeader((byte) 0x30, seqBodyLen, encoded, idx);
        for (int i = 0; i < encodedCerts.length; i++) {
            idx += arraycopy(encodedCerts[i], encoded, idx);
        }
    }

    @Override
    public int encodedLength() {
        return encodedLen;
    }

    @Override
    public int write(byte[] out, int offset) {
        return arraycopy(encoded, out, offset);
    }

}
