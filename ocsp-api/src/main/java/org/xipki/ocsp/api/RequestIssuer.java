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

package org.xipki.ocsp.api;

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.ASN1Type;
import org.xipki.common.util.CompareUtil;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class RequestIssuer {

    private final HashAlgoType hashAlgo;

    private final byte[] data;

    private final int from;

    private final int nameHashFrom;

    private final int len;

    public RequestIssuer(HashAlgoType hashAlgo, byte[] hashData) {
        int algIdLen = 2 + hashAlgo.encodedLength() + 2;
        data = new byte[algIdLen + hashData.length];
        int offset = 0;
        data[offset++] = 0x30;
        data[offset++] = (byte) (hashAlgo.encodedLength() + 2);
        offset += hashAlgo.write(data, offset);
        data[offset++] = 0x05;
        data[offset++] = 0x00;

        this.nameHashFrom = offset;
        offset += ASN1Type.arraycopy(hashData, data, offset);
        this.from = 0;
        this.len = offset;
        this.hashAlgo = hashAlgo;
    }

    public RequestIssuer(byte[] data) {
        this(data, 0, data.length);
    }

    public RequestIssuer(byte[] data, int from, int len) {
        this.data = data;
        this.from = from;
        this.len = len;
        this.hashAlgo = HashAlgoType.getInstanceForEncoded(data,
                from + 2, 2 + data[from + 3]);

        int hashAlgoFieldLen = 0xFF & data[from + 1];
        this.nameHashFrom = from + 2 + hashAlgoFieldLen;
    }

    public HashAlgoType hashAlgorithm() {
        return hashAlgo;
    }

    public String hashAlgorithmOID() {
        if (hashAlgo != null) {
            return hashAlgo.oid().getId();
        } else {
            final int start = from + 2;
            byte[] bytes = Arrays.copyOfRange(data, start, start + 2 + (0xFF & data[from + 3]));
            return ASN1ObjectIdentifier.getInstance(bytes).getId();
        }
    }

    public int from() {
        return from;
    }

    public byte[] data() {
        return data;
    }

    public int nameHashFrom() {
        return nameHashFrom;
    }

    public int length() {
        return len;
    }

    public int write(final byte[] out, final int offset) {
        System.arraycopy(data, from, out, offset, len);
        return len;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof RequestIssuer)) {
            return false;
        }

        RequestIssuer other = (RequestIssuer) obj;
        if (this.len != other.len) {
            return false;
        }

        return CompareUtil.areEqual(this.data, this.from, other.data, other.from, this.len);
    }

    @Override
    public String toString() {
        return Hex.toHexString(data, from, len);
    }

}
