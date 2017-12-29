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

import org.xipki.common.ASN1Type;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class SingleResponse extends ASN1Type {

    private final CertID certId;

    private final byte[] certStatus;

    private final Date thisUpdate;

    private final Date nextUpdate;

    private final Extensions extensions;

    private final int bodyLength;

    private final int encodedLength;

    public SingleResponse(CertID certId, byte[] certStatus, Date thisUpdate, Date nextUpdate,
            Extensions extensions) {
        this.certId = certId;
        this.certStatus = certStatus;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.extensions = extensions;

        int len = certId.encodedLength();
        len += certStatus.length;
        len += 17; // thisUpdate
        if (nextUpdate != null) {
            len += 2; // explicit tag
            len += 17;
        }

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
        idx += certId.write(out, idx);
        idx += arraycopy(certStatus, out, idx);
        idx += writeGeneralizedTime(thisUpdate, out, idx);
        if (nextUpdate != null) {
            idx += writeHeader((byte) 0xa0, 17, out, idx);
            idx += writeGeneralizedTime(nextUpdate, out, idx);
        }

        if (extensions != null) {
            idx += writeHeader((byte) 0xa1, extensions.encodedLength(), out, idx);
            idx += extensions.write(out, idx);
        }
        return idx - offset;
    }

}
