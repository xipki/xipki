// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.util.Objects;

/**
 * Utility class for the comparison.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CompareUtil {

  private CompareUtil() {
  }

  public static boolean equalsObject(Object oa, Object ob) {
    return Objects.equals(oa, ob);
  }

  public static boolean areEqual(byte[] a1, int a1Pos, byte[] a2, int a2Pos, int len) {
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

}
