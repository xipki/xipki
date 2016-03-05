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

package org.xipki.commons.security.impl.util;

import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SecurityUtil {

    private SecurityUtil() {
    }

    public static byte[] leftmost(
            final byte[] bytes,
            final int bitCount) {
        ParamUtil.requireNonNull("bytes", bytes);
        int byteLenKey = (bitCount + 7) / 8;

        if (bitCount >= (bytes.length << 3)) {
            return bytes;
        }

        byte[] truncatedBytes = new byte[byteLenKey];
        System.arraycopy(bytes, 0, truncatedBytes, 0, byteLenKey);

        // shift the bits to the right
        if (bitCount % 8 > 0) {
            int shiftBits = 8 - (bitCount % 8);

            for (int i = byteLenKey - 1; i > 0; i--) {
                truncatedBytes[i] = (byte)
                        ((byte2int(truncatedBytes[i]) >>> shiftBits)
                        | ((byte2int(truncatedBytes[i - 1]) << (8 - shiftBits)) & 0xFF));
            }
            truncatedBytes[0] = (byte) (byte2int(truncatedBytes[0]) >>> shiftBits);
        }

        return truncatedBytes;
    }

    private static int byte2int(
            final byte b) {
        return (b >= 0)
                ? b
                : 256 + b;
    }

}
