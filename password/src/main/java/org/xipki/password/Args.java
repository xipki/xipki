// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Objects;

/**
 * Utility class to validate the parameters.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class Args {

  private static final SecureRandom random = new SecureRandom();

  private Args() {
  }

  static boolean isBlank(String str) {
    return str == null || str.isEmpty();
  }

  static boolean isNotBlank(String str) {
    return str != null && !str.isEmpty();
  }

  static byte[] toUtf8Bytes(String str) {
    return (str == null) ? null : str.getBytes(StandardCharsets.UTF_8);
  }

  static boolean startsWithIgnoreCase(String str, String prefix) {
    if (str.length() < prefix.length()) {
      return false;
    }

    return prefix.equalsIgnoreCase(str.substring(0, prefix.length()));
  }

  static boolean orEqualsIgnoreCase(String str, String... tokens) {
    if (str == null) {
      return false;
    }

    for (String token : tokens) {
      if (str.equalsIgnoreCase(token)) {
        return true;
      }
    }
    return false;
  }

  static char[] merge(char[][] parts) {
    int sum = 0;
    for (char[] chars : parts) {
      sum += chars.length;
    }

    char[] ret = new char[sum];
    int destPos = 0;
    for (char[] part : parts) {
      System.arraycopy(part, 0, ret, destPos, part.length);
      destPos += part.length;
    }
    return ret;
  }

  static int nextInt(int bound) {
    return random.nextInt(bound);
  }

  static byte[] nextBytes(int num) {
    byte[] bytes = new byte[num];
    random.nextBytes(bytes);
    return bytes;
  }

  static boolean isNotEmpty(Collection<?> col) {
    return col != null && !col.isEmpty();
  }

  static int positive(int argument, String name) {
    if (argument < 1) {
      throw new IllegalArgumentException(String.format("%s may not be non-positive: %d", name, argument));
    }
    return argument;
  }

  static int min(int argument, String name, int min) {
    if (argument < min) {
      throw new IllegalArgumentException(String.format("%s may not be less than %d: %d", name, min, argument));
    }
    return argument;
  }

  static int range(int argument, String name, int min, int max) {
    if (argument < min || argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be out of the range [%d, %d]: %d", name, min, max, argument));
    }
    return argument;
  }

  static <T> T notNull(T argument, String name) {
    return Objects.requireNonNull(argument, name + " may not be null");
  }

  static String notBlank(String argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (isBlank(argument)) {
      throw new IllegalArgumentException(name + " may not be blank");
    }
    return argument;
  }

}
