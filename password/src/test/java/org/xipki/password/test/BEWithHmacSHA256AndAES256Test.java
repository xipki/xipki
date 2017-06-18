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
public class BEWithHmacSHA256AndAES256Test {

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

}
