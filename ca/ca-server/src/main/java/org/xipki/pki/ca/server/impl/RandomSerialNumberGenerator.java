/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.server.impl;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class RandomSerialNumberGenerator {

    private static int MASK_1 = 1;
    private static int MASK_2 = 3;
    private static int MASK_3 = 7;
    private static int MASK_4 = 15;
    private static int MASK_5 = 31;
    private static int MASK_6 = 63;
    private static int MASK_7 = 127;

    private static RandomSerialNumberGenerator instance;

    private final SecureRandom random;

    private RandomSerialNumberGenerator() {
        this.random = new SecureRandom();
    }

    public BigInteger nextSerialNumber(int bitLen) {
        byte[] rdnBytes = new byte[(bitLen + 7) / 8];
        random.nextBytes(rdnBytes);
        int ci = bitLen % 8;

        switch (ci) {
        case 1:
            rdnBytes[0] = (byte) (rdnBytes[0] & MASK_1);
            break;
        case 2:
            rdnBytes[0] = (byte) (rdnBytes[0] & MASK_2);
            break;
        case 3:
            rdnBytes[0] = (byte) (rdnBytes[0] & MASK_3);
            break;
        case 4:
            rdnBytes[0] = (byte) (rdnBytes[0] & MASK_4);
            break;
        case 5:
            rdnBytes[0] = (byte) (rdnBytes[0] & MASK_5);
            break;
        case 6:
            rdnBytes[0] = (byte) (rdnBytes[0] & MASK_6);
            break;
        case 7:
            rdnBytes[0] = (byte) (rdnBytes[0] & MASK_7);
            break;
        default:
            break;
        }

        return new BigInteger(1, rdnBytes);
    }

    public static synchronized RandomSerialNumberGenerator getInstance() {
        if (instance == null) {
            instance = new RandomSerialNumberGenerator();
        }
        return instance;
    }

}
