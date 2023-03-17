// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.util.*;

/**
 * Utility class for operations on {@link Collection}, {@link Set}, {@link List}, {@link Map},
 * and arrays.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CollectionUtil {

  private CollectionUtil() {
  }

  public static boolean isEmpty(Collection<?> col) {
    return col == null || col.isEmpty();
  }

  public static boolean isEmpty(Object[] arrays) {
    return arrays == null || arrays.length == 0;
  }

  public static boolean isEmpty(Map<?, ?> map) {
    return map == null || map.isEmpty();
  }

  public static boolean isNotEmpty(Collection<?> col) {
    return col != null && !col.isEmpty();
  }

  public static boolean isNotEmpty(Object[] arrays) {
    return arrays != null && arrays.length > 0;
  }

  public static boolean isNotEmpty(Map<?, ?> map) {
    return map != null && !map.isEmpty();
  }

  @Deprecated
  public static boolean isNonEmpty(Collection<?> col) {
    return col != null && !col.isEmpty();
  }

  @Deprecated
  public static boolean isNonEmpty(Object[] arrays) {
    return arrays != null && arrays.length > 0;
  }

  @Deprecated
  public static boolean isNonEmpty(Map<?, ?> map) {
    return map != null && !map.isEmpty();
  }

  public static <K, V> Map<K, V> unmodifiableMap(Map<? extends K, ? extends V> map) {
    return (map == null) ? Collections.emptyMap() : Collections.unmodifiableMap(map);
  }

  public static List<String> toLowerCaseList(List<String> list) {
    if (list == null) {
      return null;
    }

    List<String> upperList = new ArrayList<>(list.size());
    for (String s : list) {
      upperList.add(s.toLowerCase());
    }
    return upperList;
  }

  public static Set<String> toLowerCaseSet(Set<String> set) {
    if (set == null) {
      return null;
    }

    Set<String> lowerSet = new HashSet<>();
    for (String s : set) {
      lowerSet.add(s.toLowerCase());
    }
    return lowerSet;
  }

  public static <T> Set<T> unmodifiableSet(Set<? extends T> set) {
    return (set == null) ? Collections.emptySet() : Collections.unmodifiableSet(set);
  }

  public static <T> Collection<T> unmodifiableCollection(Collection<? extends T> col) {
    return (col == null) ? Collections.emptySet() : Collections.unmodifiableCollection(col);
  }

  public static <T> List<T> unmodifiableList(List<? extends T> list) {
    return (list == null) ? Collections.emptyList() : Collections.unmodifiableList(list);
  }

  public static <T> Set<T> asUnmodifiableSet(T... list) {
    return Collections.unmodifiableSet(asSet(list));
  }

  public static <T> Set<T> asSet(T... list) {
    if (list == null) {
      return Collections.emptySet();
    }
    return new HashSet<>(Arrays.asList(list));
  }

  public static <T> Set<T> listToSet(List<? extends T> list) {
    if (list == null) {
      return Collections.emptySet();
    }
    return new HashSet<>(list);
  }

  public static <T extends Comparable<? super T>> List<T> sort(Collection<T> col) {
    if (col == null) {
      return null;
    } else {
      List<T> list = new ArrayList<>(col);
      Collections.sort(list);
      return list;
    }
  }

}
