// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.misc;

import java.security.SecureRandom;

/**
 * Random utility class.
 *
 * @author Lijun Liao (xipki)
 */

public class RandomUtil {
  private static final SecureRandom random = new SecureRandom();

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
