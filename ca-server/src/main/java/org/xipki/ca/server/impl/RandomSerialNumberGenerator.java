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

package org.xipki.ca.server.impl;

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
