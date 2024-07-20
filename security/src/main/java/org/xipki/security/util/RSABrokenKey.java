// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;
/*
 * Credits: ported to Java by Martin Paljak
 * https://github.com/crocs-muni/roca
 *
 * ROCA detector using the moduli detector.
 * This detector port is unmaintained. Please refer to the original Python
 * implementation for more details.
 */

import java.math.BigInteger;

/**
 * RSA broken key checker.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */
public class RSABrokenKey {

  private static final BigInteger ONE = BigInteger.ONE;
  private static final BigInteger ZERO = BigInteger.ZERO;

  private static final BigInteger[] primes;

  private static final BigInteger[] markers;

  static {
    int[] ints = new int[]{
      3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
      89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167};

    primes = new BigInteger[ints.length];
    for (int i = 0; i < ints.length; i++) {
      primes[i] = BigInteger.valueOf(ints[i]);
    }

    String[] strs = new String[]{
      "6", "1e", "7e", "402", "161a", "1a316", "30af2", "7ffffe", "1ffffffe", "7ffffffe",
      "4000402", "1fffffffffe", "7fffffffffe", "7ffffffffffe", "12dd703303aed2",
      "7fffffffffffffe", "1434026619900b0a", "7fffffffffffffffe", "1164729716b1d977e",
      "147811a48004962078a", "b4010404000640502", "7fffffffffffffffffffe",
      "1fffffffffffffffffffffe", "1000000006000001800000002", "1ffffffffffffffffffffffffe",
      "16380e9115bd964257768fe396", "27816ea9821633397be6a897e1a",
      "1752639f4e85b003685cbe7192ba", "1fffffffffffffffffffffffffffe",
      "6ca09850c2813205a04c81430a190536", "7fffffffffffffffffffffffffffffffe",
      "1fffffffffffffffffffffffffffffffffe", "7fffffffffffffffffffffffffffffffffe",
      "1ffffffffffffffffffffffffffffffffffffe", "50c018bc00482458dac35b1a2412003d18030a",
      "161fb414d76af63826461899071bd5baca0b7e1a", "7fffffffffffffffffffffffffffffffffffffffe",
      "7ffffffffffffffffffffffffffffffffffffffffe"};

    markers = new BigInteger[strs.length];
    for (int i = 0; i < markers.length; i++) {
      markers[i] = new BigInteger(strs[i], 16);
    }
  } // method static

  public static boolean isAffected(BigInteger modulus) {
    for (int i = 0; i < primes.length; i++) {
      BigInteger bi = ONE.shiftLeft(modulus.remainder(primes[i]).intValue());
      if (bi.and(markers[i]).equals(ZERO)) {
        return false;
      }
    }

    return true;
  }
}
