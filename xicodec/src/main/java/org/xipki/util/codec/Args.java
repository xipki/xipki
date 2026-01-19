// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Utility class to validate the parameters.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class Args {

  private Args() {
  }

  public static boolean isAllZeros(byte[] bytes) {
    if (bytes.length == 0) {
      return false;
    }

    for (byte b : bytes) {
      if (b != 0) {
        return false;
      }
    }
    return true;
  }

  public static boolean isBlank(String str) {
    return str == null || str.isEmpty();
  }

  public static boolean isNotBlank(String str) {
    return str == null || str.isEmpty();
  }

  public static boolean isNumber(String str) {
    return isNumber(str, 10);
  }

  public static boolean isNumber(String str, int radix) {
    try {
      new BigInteger(Args.notNull(str, "str"), radix);
      return true;
    } catch (NumberFormatException ex) {
      return false;
    }
  }

  public static int positive(int argument, String name) {
    if (argument < 1) {
      throw new IllegalArgumentException(String.format(
          "%s may not be non-positive: %d", name, argument));
    }
    return argument;
  }

  public static long positive(long argument, String name) {
    if (argument < 1) {
      throw new IllegalArgumentException(String.format(
          "%s may not be non-positive: %d", name, argument));
    }
    return argument;
  }

  public static BigInteger positive(BigInteger argument, String name) {
    Args.notNull(argument, name);
    if (argument.signum() != 1) {
      throw new IllegalArgumentException(name + " must not be non-positive");
    }
    return argument;
  }

  public static int notNegative(int argument, String name) {
    if (argument < 0) {
      throw new IllegalArgumentException(String.format(
          "%s may not be negative: %d", name, argument));
    }
    return argument;
  }

  public static long notNegative(long argument, String name) {
    if (argument < 0) {
      throw new IllegalArgumentException(String.format(
          "%s may not be negative: %d", name, argument));
    }
    return argument;
  }

  public static BigInteger notNegative(BigInteger argument, String name) {
    Args.notNull(argument, name);
    if (argument.signum() == -1) {
      throw new IllegalArgumentException(name + " must not be negative");
    }
    return argument;
  }

  public static byte equals(byte argument, String name, byte value) {
    if (argument != value) {
      throw new IllegalArgumentException(String.format(
          "%s may not be other than %d: %d", name, value, argument));
    }
    return argument;
  }

  public static int equals(int argument, String name, int value) {
    if (argument != value) {
      throw new IllegalArgumentException(String.format(
          "%s may not be other than %d: %d", name, value, argument));
    }
    return argument;
  }

  public static long equals(long argument, String name, long value) {
    if (argument != value) {
      throw new IllegalArgumentException(String.format(
          "%s may not be other than %d: %d", name, value, argument));
    }
    return argument;
  }

  public static int min(int argument, String name, int min) {
    if (argument < min) {
      throw new IllegalArgumentException(String.format(
          "%s may not be less than %d: %d", name, min, argument));
    }
    return argument;
  }

  public static long min(long argument, String name, long min) {
    if (argument < min) {
      throw new IllegalArgumentException(String.format(
          "%s may not be less than %d: %d", name, min, argument));
    }
    return argument;
  }

  public static int max(int argument, String name, int max) {
    if (argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be greater than %d: %d", name, max, argument));
    }
    return argument;
  }

  public static long max(long argument, String name, long max) {
    if (argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be greater than %d: %d", name, max, argument));
    }
    return argument;
  }

  public static int range(int argument, String name, int min, int max) {
    if (argument < min || argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be out of the range [%d, %d]: %d",
          name, min, max, argument));
    }
    return argument;
  }

  public static long range(long argument, String name, long min, long max) {
    if (argument < min || argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be out of the range [%d, %d]: %d",
          name, min, max, argument));
    }
    return argument;
  }

  public static byte[] fixedLen(byte[] argument, String name, int len) {
    Objects.requireNonNull(argument, name + " may not be null");
    equals(argument.length, name + ".length", len);
    return argument;
  }

  public static <T> T notNull(T argument, String name) {
    return Objects.requireNonNull(argument, name + " may not be null");
  }

  public static String notBlank(String argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be blank");
    }
    return argument;
  }

  public static String toNonBlankLower(String argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be blank");
    }
    return argument.toLowerCase();
  }

  public static <T> Collection<T> notEmpty(
      Collection<T> argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be empty");
    }
    return argument;
  }

  public static <T> Set<T> notEmpty(Set<T> argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be empty");
    }
    return argument;
  }

  public static <T> List<T> notEmpty(List<T> argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be empty");
    }
    return argument;
  }

  public static <K,V> Map<K,V> notEmpty(Map<K,V> argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be empty");
    }
    return argument;
  }

  public static <K,V> Dictionary<K,V> notEmpty(
      Dictionary<K,V> argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be empty");
    }
    return argument;
  }

  public static void exactOne(
      Object value1, String name1, Object value2, String name2) {
    if (value1 == null && value2 == null) {
      throw new IllegalArgumentException(name1 + " and " + name2
          + " may not be both null");
    } else if (value1 != null && value2 != null) {
      throw new IllegalArgumentException(name1 + " and " + name2
          + " may not be both non-null");
    }
  }

  public static int among(int argument, String name, int... candidates) {
    for (int candidate : candidates) {
      if (argument == candidate) {
        return argument;
      }
    }

    throw new IllegalArgumentException(name + " is not among " +
        Arrays.toString(candidates) + ": " + argument);
  }

  public static long among(long argument, String name, long... candidates) {
    for (long candidate : candidates) {
      if (argument == candidate) {
        return argument;
      }
    }

    throw new IllegalArgumentException(name + " is not among " +
        Arrays.toString(candidates) + ": " + argument);
  }

  public static byte[] notEmpty(byte[] argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.length == 0) {
      throw new IllegalArgumentException(name + " may not be empty");
    }
    return argument;
  }

  public static <T> T[] notEmpty(T[] argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.length == 0) {
      throw new IllegalArgumentException(name + " may not be empty");
    }

    for (T e : argument) {
      if (e == null) {
        throw new IllegalArgumentException(
            name + " may not contain null element");
      }
    }

    return argument;
  }

  public static <T> T[] noNullElements(T[] argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");

    for (T e : argument) {
      if (e == null) {
        throw new IllegalArgumentException(
            name + " may not contain null element");
      }
    }

    return argument;
  }

  public static <T> T[] notEmptyAndNoNullElements(T[] argument, String name) {
    notEmpty(argument, name);
    return noNullElements(argument, name);
  }

  public static byte[] notEmptyBytes(byte[] argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    positive(argument.length, name + ".length");
    return argument;
  }

  public static int[] notEmptyInts(int[] argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    positive(argument.length, name + ".length");
    return argument;
  }

}
