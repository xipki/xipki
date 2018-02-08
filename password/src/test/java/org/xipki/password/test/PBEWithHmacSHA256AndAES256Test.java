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

package org.xipki.password.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.password.PBEAlgo;
import org.xipki.password.PasswordBasedEncryption;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
public class PBEWithHmacSHA256AndAES256Test {

    private static PBEAlgo algo = PBEAlgo.PBEWithHmacSHA256AndAES_256;

    private static byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 15, 16};

    @Test
    public void encrypThenDecrypt() throws Exception {
        char[] password = "qwert".toCharArray();
        byte[] plainText = "123456".getBytes();
        int iterationCount = 1000;
        byte[] encrypted = PasswordBasedEncryption.encrypt(algo, plainText, password,
                iterationCount, salt);
        byte[] decrypted = PasswordBasedEncryption.decrypt(algo, encrypted, password,
                iterationCount, salt);
        Assert.assertArrayEquals(plainText, decrypted);
    }

    @Test
    public void decrypt() throws Exception {
        char[] password = "qwert".toCharArray();
        int iterationCount = 1000;
        byte[] encrypted = new byte[]{16, // length of IV
            -15, -2, 113, -42, -46, 43, -65, -8, -51, 48, 6, 26, -73, -38, -111, -1, // IV
            75, 76, -36, -17, -96, -123, 2, -107, 92, -27, -114, -74, -80, 105, 46, 91};
        byte[] decrypted = PasswordBasedEncryption.decrypt(algo, encrypted, password,
                iterationCount, salt);

        byte[] plainText = "123456".getBytes();
        Assert.assertArrayEquals(plainText, decrypted);
    }

}
