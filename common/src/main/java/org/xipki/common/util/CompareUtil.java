/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.common.util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CompareUtil {

    private CompareUtil() {
    }

    public static boolean equalsObject(final Object oa, final Object ob) {
        return (oa == null) ? (ob == null) : oa.equals(ob);
    }

    public static boolean areEqual(byte[] a1, int a1Pos, byte[] a2, int a2Pos, int len) {
        if (a1Pos + len > a1.length || a2Pos + len > a2.length) {
            throw new IndexOutOfBoundsException("len is too large");
        }

        for (int i = 0; i < len; i++) {
            if (a1[a1Pos + i] != a2[a2Pos + i]) {
                return false;
            }
        }

        return true;
    }

}
