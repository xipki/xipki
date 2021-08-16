/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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
 * Random serial number generator.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class RandomSerialNumberGenerator {

  private static RandomSerialNumberGenerator instance;

  private final SecureRandom random;

  private RandomSerialNumberGenerator() {
    this.random = new SecureRandom();
  }

  /**
   * Generate the next serial number.
   * @param byteLen byte length of the serial number.
   * @return the serial number.
   */
  public BigInteger nextSerialNumber(int byteLen) {
    final byte[] rndBytes = new byte[byteLen];
    random.nextBytes(rndBytes);
    // clear the highest bit.
    rndBytes[0] &= 0x7F;
    // set the second highest bit
    rndBytes[0] |= 0x40;
    return new BigInteger(rndBytes);

  } // method nextSerialNumber

  public static synchronized RandomSerialNumberGenerator getInstance() {
    if (instance == null) {
      instance = new RandomSerialNumberGenerator();
    }
    return instance;
  } // method RandomSerialNumberGenerator

}
