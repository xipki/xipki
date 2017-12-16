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

import java.io.IOException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.common.ASN1Type;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ResponderID extends ASN1Type {

    private final byte[] encoded;

    private final int encodedLength;

    public ResponderID(byte[] key) throws IOException {
        this.encoded = new org.bouncycastle.asn1.ocsp.ResponderID(
                new DEROctetString(key)).getEncoded();
        this.encodedLength = encoded.length;
    }

    public ResponderID(X500Name name) throws IOException {
        this.encoded = new org.bouncycastle.asn1.ocsp.ResponderID(name).getEncoded();
        this.encodedLength = encoded.length;
    }

    @Override
    public int encodedLength() {
        return encodedLength;
    }

    @Override
    public int write(byte[] out, int offset) {
        return arraycopy(encoded, out, offset);
    }

}
