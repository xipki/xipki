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

import java.security.SecureRandom;

/**
 * Random utility class.
 *
 * @author Lijun Liao
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
