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

package org.xipki.util;

/**
 * Utility class for the comparison.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CompareUtil {

  private CompareUtil() {
  }

  public static boolean equalsObject(Object oa, Object ob) {
    return (oa == null) ? (ob == null) : oa.equals(ob);
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
