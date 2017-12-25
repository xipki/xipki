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

import java.util.List;

import org.xipki.common.ASN1Type;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class Extensions extends ASN1Type {

    private final List<Extension> extensions;

    private final int bodyLen;

    private final int encodedLen;

    public Extensions(List<Extension> extensions) {
        int len = 0;
        for (Extension m : extensions) {
            len += m.encodedLength();
        }

        this.bodyLen = len;
        this.encodedLen = getLen(bodyLen);
        this.extensions = extensions;
    }

    @Override
    public int encodedLength() {
        return encodedLen;
    }

    @Override
    public int write(final byte[] out, final int offset) {
        int idx = offset;
        idx += writeHeader((byte) 0x30, bodyLen, out, idx);
        for (Extension m : extensions) {
            idx += m.write(out, idx);
        }
        return idx - offset;
    }

}
