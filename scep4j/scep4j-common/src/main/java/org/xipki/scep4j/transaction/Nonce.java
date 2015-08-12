/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.scep4j.transaction;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.xipki.scep4j.util.ParamChecker;

/**
 * @author Lijun Liao
 */

public class Nonce
{
    private static final SecureRandom random = new SecureRandom();
    private static final int NONCE_LEN = 16;

    private final byte[] bytes;

    private Nonce(
            final byte[] bytes,
            final boolean cloneBytes)
    {
        ParamChecker.assertNotNull("bytes", bytes);
        if(bytes.length != 16)
        {
            throw new IllegalArgumentException("bytes.len is not 16: " + bytes.length);
        }
        this.bytes = cloneBytes ? Arrays.clone(bytes) : bytes;
    }

    public Nonce(
            final byte[] bytes)
    {
        this(bytes, true);
    }

    public byte[] getBytes()
    {
        return Arrays.clone(bytes);
    }

    public static Nonce randomNonce()
    {
        byte[] bytes = new byte[NONCE_LEN];
        random.nextBytes(bytes);
        return new Nonce(bytes, false);
    }

}
