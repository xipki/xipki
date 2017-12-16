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

package org.xipki.ocsp.server.impl.type;

import java.math.BigInteger;

import org.xipki.common.ASN1Type;
import org.xipki.ocsp.api.RequestIssuer;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CertID extends ASN1Type {

    private final RequestIssuer issuer;

    private final BigInteger serialNumber;

    private final int bodyLength;

    private final int encodedLength;

    public CertID(RequestIssuer issuer, BigInteger serialNumber) {
        this.issuer = issuer;
        this.serialNumber = serialNumber;

        int len = issuer.length();

        int snBytesLen = 1 + serialNumber.bitLength() / 8;
        len += getLen(snBytesLen);

        this.bodyLength = len;
        this.encodedLength = getLen(bodyLength);
    }

    public RequestIssuer issuer() {
        return issuer;
    }

    public BigInteger serialNumber() {
        return serialNumber;
    }

    @Override
    public int encodedLength() {
        return encodedLength;
    }

    public int write(final byte[] out, final int offset) {
        int idx = offset;
        idx += writeHeader((byte) 0x30, bodyLength, out, idx);
        idx += issuer.write(out, idx);

        // serialNumbers
        byte[] snBytes = serialNumber.toByteArray();
        idx += writeHeader((byte) 0x02, snBytes.length, out, idx);
        idx += arraycopy(snBytes, out, idx);

        return idx - offset;
    }

}
