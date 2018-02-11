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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Lijun Liao
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

    public static boolean isNonEmpty(Collection<?> col) {
        return col != null && !col.isEmpty();
    }

    public static boolean isNonEmpty(Object[] arrays) {
        return arrays != null && arrays.length > 0;
    }

    public static boolean isNonEmpty(Map<?, ?> map) {
        return map != null && !map.isEmpty();
    }

    public static <K, V> Map<K, V> unmodifiableMap(Map<? extends K, ? extends V> map) {
        if (map == null) {
            return Collections.emptyMap();
        }

        return Collections.unmodifiableMap(map);
    }

    public static List<String> toLowerCaseList(List<String> list) {
        if (list == null) {
            return list;
        }

        List<String> upperList = new ArrayList<>(list.size());
        for (String s : list) {
            upperList.add(s.toLowerCase());
        }
        return upperList;
    }

    public static Set<String> toLowerCaseSet(Set<String> set) {
        if (set == null) {
            return set;
        }

        Set<String> upperSet = new HashSet<>();
        for (String s : set) {
            upperSet.add(s.toLowerCase());
        }
        return upperSet;
    }

    public static <T> Set<T> unmodifiableSet(Set<? extends T> set) {
        if (set == null) {
            return Collections.emptySet();
        }

        return Collections.unmodifiableSet(set);
    }

    public static <T> Collection<T> unmodifiableCollection(Collection<? extends T> col) {
        if (col == null) {
            return Collections.emptySet();
        }

        return Collections.unmodifiableCollection(col);
    }

    public static <T> List<T> unmodifiableList(List<? extends T> list) {
        if (list == null) {
            return Collections.emptyList();
        }

        return Collections.unmodifiableList(list);
    }

}
