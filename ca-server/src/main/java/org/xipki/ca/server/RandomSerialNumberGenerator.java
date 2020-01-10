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

import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.util.Args;

/**
 * Random serial number generator.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class RandomSerialNumberGenerator {

  private static int[] AND_MASKS = new int[] {0xFF, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F};

  private static int[]  OR_MASKS = new int[] {0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

  private static RandomSerialNumberGenerator instance;

  private final SecureRandom random;

  private RandomSerialNumberGenerator() {
    this.random = new SecureRandom();
  }

  /**
   * Generate the next serial number.
   * @param bitLen bit length of the serial number.
   * @return the serial number.
   */
  public BigInteger nextSerialNumber(int bitLen) {
    Args.range(bitLen, "bitlen", CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
    final byte[] rdnBytes = new byte[(bitLen + 7) / 8];
    final int ci = bitLen % 8;
    final int minWeight = bitLen >>> 2;

    while (true) {
      random.nextBytes(rdnBytes);
      if (ci != 0) {
        rdnBytes[0] = (byte) (rdnBytes[0] & AND_MASKS[ci]);
      }
      rdnBytes[0] = (byte) (rdnBytes[0] | OR_MASKS[ci]);

      // check NAF weight
      BigInteger bi = new BigInteger(1, rdnBytes);

      BigInteger threeBi = bi.shiftLeft(1).add(bi);
      BigInteger diff = threeBi.xor(bi);
      int nafWeight = diff.bitCount();
      if (nafWeight >= minWeight) {
        return bi;
      }
    }

  } // method nextSerialNumber

  public static synchronized RandomSerialNumberGenerator getInstance() {
    if (instance == null) {
      instance = new RandomSerialNumberGenerator();
    }
    return instance;
  } // method RandomSerialNumberGenerator

}
