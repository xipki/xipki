/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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
import java.util.Collections;
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

    public static boolean isEmpty(
            final Collection<?> col) {
        return col == null || col.isEmpty();
    }

    public static boolean isEmpty(
            final Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

    public static boolean isNonEmpty(
            final Collection<?> col) {
        return col != null && !col.isEmpty();
    }

    public static boolean isNonEmpty(
            final Map<?, ?> map) {
        return map != null && !map.isEmpty();
    }

    public static <K, V> Map<K, V> unmodifiableMap(
            final Map<? extends K, ? extends V> map) {
        if (map == null) {
            return Collections.emptyMap();
        }

        return Collections.unmodifiableMap(map);
    }

    public static <T> Set<T> unmodifiableSet(
            final Set<? extends T> set) {
        if (set == null) {
            return Collections.emptySet();
        }

        return Collections.unmodifiableSet(set);
    }

    public static <T> Collection<T> unmodifiableCollection(
            final Collection<? extends T> col) {
        if (col == null) {
            return Collections.emptySet();
        }

        return Collections.unmodifiableCollection(col);
    }

    public static <T> List<T> unmodifiableList(
            final List<? extends T> list) {
        if (list == null) {
            return Collections.emptyList();
        }

        return Collections.unmodifiableList(list);
    }

}
