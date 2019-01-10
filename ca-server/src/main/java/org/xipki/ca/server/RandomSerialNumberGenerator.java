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

package org.xipki.ca.server;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class RandomSerialNumberGenerator {

  private static int[] MASKS = new int[] {-1, 1, 3, 7, 15, 31, 63, 127};

  private static RandomSerialNumberGenerator instance;

  private final SecureRandom random;

  private RandomSerialNumberGenerator() {
    this.random = new SecureRandom();
  }

  public BigInteger nextSerialNumber(int bitLen) {
    byte[] rdnBytes = new byte[(bitLen + 7) / 8];
    random.nextBytes(rdnBytes);
    int ci = bitLen % 8;
    if (ci != 0) {
      rdnBytes[0] = (byte) (rdnBytes[0] & MASKS[ci]);
    }

    return new BigInteger(1, rdnBytes);
  }

  public static synchronized RandomSerialNumberGenerator getInstance() {
    if (instance == null) {
      instance = new RandomSerialNumberGenerator();
    }
    return instance;
  }

}
