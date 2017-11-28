/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ParamUtil {

    private ParamUtil() {
    }

    public static int requireMin(final String objName, final int obj, final int min) {
        if (obj < min) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be less than %d: %d", objName, min, obj));
        }
        return obj;
    }

    public static long requireMin(final String objName, final long obj, final long min) {
        if (obj < min) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be less than %d: %d", objName, min, obj));
        }
        return obj;
    }

    public static int requireMax(final String objName, final int obj, final int max) {
        if (obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be greater than %d: %d", objName, max, obj));
        }
        return obj;
    }

    public static long requireMax(final String objName, final long obj, final long max) {
        if (obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be greater than %d: %d", objName, max, obj));
        }
        return obj;
    }

    public static int requireRange(final String objName, final int obj, final int min,
            final int max) {
        if (obj < min || obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be out of the range [%d, %d]: %d", objName, min, max, obj));
        }
        return obj;
    }

    public static long requireRange(final String objName, final long obj, final long min,
            final long max) {
        if (obj < min || obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be out of the range [%d, %d]: %d", objName, min, max, obj));
        }
        return obj;
    }

    public static <T> T requireNonNull(final String objName, final T obj) {
        return Objects.requireNonNull(obj, objName + " must not be null");
    }

    public static String requireNonBlank(final String objName, final String obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be blank");
        }
        return obj;
    }

    public static <T> Collection<T> requireNonEmpty(final String objName,
            final Collection<T> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <T> Set<T> requireNonEmpty(final String objName,
            final Set<T> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <T> List<T> requireNonEmpty(final String objName,
            final List<T> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <K,V> Map<K,V> requireNonEmpty(final String objName,
            final Map<K,V> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <K,V> Dictionary<K,V> requireNonEmpty(final String objName,
            final Dictionary<K,V> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

}
