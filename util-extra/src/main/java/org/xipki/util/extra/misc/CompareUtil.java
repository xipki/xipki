// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.misc;

import java.util.Arrays;

/**
 * Utility class for the comparison.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CompareUtil {

  private CompareUtil() {
  }

  public static boolean areEqual(
      byte[] a1, int a1Pos, byte[] a2, int a2Pos, int len) {
    if (a1Pos + len > a1.length || a2Pos + len > a2.length) {
      throw new IndexOutOfBoundsException("len is too large");
    }

    for (int i = 0; i < len; i++) {
      if (a1[a1Pos + i] != a2[a2Pos + i]) {
        return false;
      }
    }

    return true;
  }

  public static boolean equals(Object a, Object b) {
    if (a == b) {
      return true;
    } else if (a == null) {
      return false;
    } else {
      if (b == null) {
        return false;
      }
    }

    if (a instanceof byte[]) {
      if (b instanceof byte[]) {
        return Arrays.equals((byte[]) a, (byte[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof int[]) {
      if (b instanceof int[]) {
        return Arrays.equals((int[]) a, (int[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof long[]) {
      if (b instanceof long[]) {
        return Arrays.equals((long[]) a, (long[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof boolean[]) {
      if (b instanceof boolean[]) {
        return Arrays.equals((boolean[]) a, (boolean[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof short[]) {
      if (b instanceof short[]) {
        return Arrays.equals((short[]) a, (short[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof char[]) {
      if (b instanceof char[]) {
        return Arrays.equals((char[]) a, (char[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof float[]) {
      if (b instanceof float[]) {
        return Arrays.equals((float[]) a, (float[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof double[]) {
      if (b instanceof double[]) {
        return Arrays.equals((double[]) a, (double[]) b);
      } else {
        return false;
      }
    }

    if (a instanceof Object[]) {
      if (b instanceof Object[]) {
        return Arrays.equals((Object[]) a, (Object[]) b);
      } else {
        return false;
      }
    }

    return a.equals(b);
  }

  public static boolean contains(int[] array, int value) {
    for (int v : array) {
      if (v == value) return true;
    }
    return false;
  }

  public static boolean contains(long[] array, long value) {
    for (long v : array) {
      if (v == value) return true;
    }
    return false;
  }

}
