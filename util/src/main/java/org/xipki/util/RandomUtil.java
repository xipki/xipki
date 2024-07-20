// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.security.SecureRandom;

/**
 * Random utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 *
 */

public class RandomUtil {
  private static final SecureRandom random = new SecureRandom();

  public static String nextHexLong() {
    return Long.toHexString(random.nextLong());
  }

  public static long nextLong() {
    return random.nextLong();
  }

  public static int nextInt() {
    return random.nextInt();
  }

  public static int nextInt(int bound) {
    return random.nextInt(bound);
  }

  public static byte[] nextBytes(int num) {
    byte[] bytes = new byte[num];
    random.nextBytes(bytes);
    return bytes;
  }

}
