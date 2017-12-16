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

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class WritableOnlyExtension extends Extension {

    private final byte[] encoded;

    private final int from;

    private final int encodedLength;

    public WritableOnlyExtension(byte[] encoded) {
        this(encoded, 0, encoded.length);
    }

    public WritableOnlyExtension(byte[] encoded, int from, int encodedLength) {
        this.encoded = encoded;
        this.from = from;
        this.encodedLength = encodedLength;
    }

    @Override
    public int encodedLength() {
        return encodedLength;
    }

    @Override
    public int write(byte[] out, int offset) {
        System.arraycopy(encoded, from, out, offset, encodedLength);
        return encodedLength;
    }

}
