/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.common.util;

import java.util.Collection;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.annotation.Nonnull;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ParamUtil {

    private ParamUtil() {
    }

    public static int requireMin(
            @Nonnull final String objName,
            final int obj,
            final int min) {
        if (obj < min) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be less than %d: %d", objName, min, obj));
        }
        return obj;
    }

    public static long requireMin(
            @Nonnull final String objName,
            final long obj,
            final long min) {
        if (obj < min) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be less than %d: %d", objName, min, obj));
        }
        return obj;
    }

    public static int requireMax(
            @Nonnull final String objName,
            final int obj,
            final int max) {
        if (obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be greater than %d: %d", objName, max, obj));
        }
        return obj;
    }

    public static long requireMax(
            @Nonnull final String objName,
            final long obj,
            final long max) {
        if (obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be greater than %d: %d", objName, max, obj));
        }
        return obj;
    }

    public static int requireRange(
            @Nonnull final String objName,
            final int obj,
            final int min,
            final int max) {
        if (obj < min || obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be out of the range [%d, %d]: %d", objName, min, max, obj));
        }
        return obj;
    }

    public static long requireRange(
            @Nonnull final String objName,
            final long obj,
            final long min,
            final long max) {
        if (obj < min || obj > max) {
            throw new IllegalArgumentException(String.format(
                    "%s must not be out of the range [%d, %d]: %d", objName, min, max, obj));
        }
        return obj;
    }

    public static <T> T requireNonNull(
            @Nonnull final String objName,
            @Nonnull final T obj) {
        return Objects.requireNonNull(obj, objName + " must not be null");
    }

    public static String requireNonBlank(
            @Nonnull final String objName,
            @Nonnull final String obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be blank");
        }
        return obj;
    }

    public static <T> Collection<T> requireNonEmpty(
            @Nonnull final String objName,
            @Nonnull final Collection<T> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <T> Set<T> requireNonEmpty(
            @Nonnull final String objName,
            @Nonnull final Set<T> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <T> List<T> requireNonEmpty(
            @Nonnull final String objName,
            @Nonnull final List<T> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <K,V> Map<K,V> requireNonEmpty(
            @Nonnull final String objName,
            @Nonnull final Map<K,V> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

    public static <K,V> Dictionary<K,V> requireNonEmpty(
            @Nonnull final String objName,
            @Nonnull final Dictionary<K,V> obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be empty");
        }
        return obj;
    }

}
