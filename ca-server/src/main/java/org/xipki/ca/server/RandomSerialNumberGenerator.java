// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Random serial number generator.
 *
 * @author Lijun Liao (xipki)
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
    // set the second-highest bit
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
