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

package org.xipki.scep.transaction;

import java.security.SecureRandom;
import java.util.Arrays;

import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Nonce {

  private static final SecureRandom RANDOM = new SecureRandom();

  private static final int NONCE_LEN = 16;

  private final byte[] bytes;

  private Nonce(byte[] bytes, boolean cloneBytes) {
    ScepUtil.requireNonNull("bytes", bytes);
    if (bytes.length != 16) {
      throw new IllegalArgumentException("bytes.length is not of 16");
    }
    this.bytes = cloneBytes ? Arrays.copyOf(bytes, bytes.length) : bytes;
  }

  public Nonce(byte[] bytes) {
    this(bytes, true);
  }

  public byte[] getBytes() {
    return Arrays.copyOf(bytes, bytes.length);
  }

  public static Nonce randomNonce() {
    byte[] bytes = new byte[NONCE_LEN];
    RANDOM.nextBytes(bytes);
    return new Nonce(bytes, false);
  }

}
