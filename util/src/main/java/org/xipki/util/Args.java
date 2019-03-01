/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.util.Collection;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Args {

  private Args() {
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
          "%s may not be out of the range [%d, %d]: %d", name, min, max, argument));
    }
    return argument;
  }

  public static long range(long argument, String name, long min, long max) {
    if (argument < min || argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be out of the range [%d, %d]: %d", name, min, max, argument));
    }
    return argument;
  }

  public static <T> T notNull(T argument, String name) {
    return Objects.requireNonNull(argument, name + " may not be null");
  }

  public static String notBlank(String argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (isBlank(argument)) {
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

  public static <T> Collection<T> notEmpty(Collection<T> argument, String name) {
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

  public static <K,V> Dictionary<K,V> notEmpty(Dictionary<K,V> argument, String name) {
    Objects.requireNonNull(argument, name + " may not be null");
    if (argument.isEmpty()) {
      throw new IllegalArgumentException(name + " may not be empty");
    }
    return argument;
  }

  private static boolean isBlank(final CharSequence text) {
    if (text == null) {
      return true;
    }
    for (int i = 0; i < text.length(); i++) {
      if (!Character.isWhitespace(text.charAt(i))) {
        return false;
      }
    }
    return true;
  }

}
