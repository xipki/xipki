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

package org.xipki.security.pkcs11;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DigestOutputStream extends OutputStream {

    private Digest digest;

    public DigestOutputStream(final Digest digest) {
        this.digest = digest;
    }

    public void reset() {
        digest.reset();
    }

    @Override
    public void write(final byte[] bytes, final int off, final int len) throws IOException {
        digest.update(bytes, off, len);
    }

    @Override
    public void write(final byte[] bytes) throws IOException {
        digest.update(bytes, 0, bytes.length);
    }

    @Override
    public void write(final int oneByte) throws IOException {
        digest.update((byte) oneByte);
    }

    public byte[] digest() {
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        reset();
        return result;
    }

}
