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

import java.util.Date;
import java.util.List;

import org.xipki.common.ASN1Type;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ResponseData extends ASN1Type {

    private final int version;

    private final ResponderID responderId;

    private final Date producedAt;

    private final List<SingleResponse> responses;

    private final Extensions extensions;

    private final int bodyLength;

    private final int encodedLength;

    public ResponseData(int version, ResponderID responderId, Date producedAt,
            List<SingleResponse> responses, Extensions extensions) {
        if (version < 0 || version > 127) {
            throw new IllegalArgumentException("invalid version: " + version);
        }
        this.version = version;
        this.responderId = responderId;
        this.producedAt = producedAt;
        this.responses = responses;
        this.extensions = extensions;

        int len = 0;
        if (version != 0) {
            len += 5;
        }
        len += responderId.encodedLength();

        // producedAt
        len += 17;

        // responses
        int responsesBodyLen = 0;
        for (SingleResponse sr : responses) {
            responsesBodyLen += sr.encodedLength();
        }
        len += getLen(responsesBodyLen);

        // extensions
        if (extensions != null) {
            len += getLen(extensions.encodedLength()); // explicit tag
        }

        this.bodyLength = len;
        this.encodedLength = getLen(bodyLength);
    }

    @Override
    public int encodedLength() {
        return encodedLength;
    }

    @Override
    public int write(byte[] out, int offset) {
        int idx = offset;
        idx += writeHeader((byte) 0x30, bodyLength, out, idx);

        // version
        if (version != 0) {
            idx += writeHeader((byte) 0xa0, 3, out, idx);
            idx += writeHeader((byte) 0x02, 1, out, idx);
            out[idx++] = (byte) version;
        }

        idx += responderId.write(out, idx);
        idx += writeGeneralizedTime(producedAt, out, idx);

        // responses
        int responsesBodyLen = 0;
        for (SingleResponse sr : responses) {
            responsesBodyLen += sr.encodedLength();
        }
        idx += writeHeader((byte) 0x30, responsesBodyLen, out, idx);
        for (SingleResponse sr : responses) {
            idx += sr.write(out, idx);
        }

        if (extensions != null) {
            idx += writeHeader((byte) 0xa1, extensions.encodedLength(), out, idx);
            idx += extensions.write(out, idx);
        }

        return idx - offset;
    }

}
