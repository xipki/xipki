/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.common.util;

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

public class ParamUtil {

  private ParamUtil() {
  }

  public static int requireMin(String objName, int obj, int min) {
    if (obj < min) {
      throw new IllegalArgumentException(String.format(
          "%s must not be less than %d: %d", objName, min, obj));
    }
    return obj;
  }

  public static long requireMin(String objName, long obj, long min) {
    if (obj < min) {
      throw new IllegalArgumentException(String.format(
          "%s must not be less than %d: %d", objName, min, obj));
    }
    return obj;
  }

  public static int requireMax(String objName, int obj, int max) {
    if (obj > max) {
      throw new IllegalArgumentException(String.format(
          "%s must not be greater than %d: %d", objName, max, obj));
    }
    return obj;
  }

  public static long requireMax(String objName, long obj, long max) {
    if (obj > max) {
      throw new IllegalArgumentException(String.format(
          "%s must not be greater than %d: %d", objName, max, obj));
    }
    return obj;
  }

  public static int requireRange(String objName, int obj, int min, int max) {
    if (obj < min || obj > max) {
      throw new IllegalArgumentException(String.format(
          "%s must not be out of the range [%d, %d]: %d", objName, min, max, obj));
    }
    return obj;
  }

  public static long requireRange(String objName, long obj, long min, long max) {
    if (obj < min || obj > max) {
      throw new IllegalArgumentException(String.format(
          "%s must not be out of the range [%d, %d]: %d", objName, min, max, obj));
    }
    return obj;
  }

  public static <T> T requireNonNull(String objName, T obj) {
    return Objects.requireNonNull(obj, objName + " must not be null");
  }

  public static String requireNonBlank(String objName, String obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be blank");
    }
    return obj;
  }

  public static String requireNonBlankLower(String objName, String obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be blank");
    }
    return obj.toLowerCase();
  }

  public static <T> Collection<T> requireNonEmpty(String objName, Collection<T> obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be empty");
    }
    return obj;
  }

  public static <T> Set<T> requireNonEmpty(String objName, Set<T> obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be empty");
    }
    return obj;
  }

  public static <T> List<T> requireNonEmpty(String objName, List<T> obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be empty");
    }
    return obj;
  }

  public static <K,V> Map<K,V> requireNonEmpty(String objName, Map<K,V> obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be empty");
    }
    return obj;
  }

  public static <K,V> Dictionary<K,V> requireNonEmpty(String objName, Dictionary<K,V> obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be empty");
    }
    return obj;
  }

}
