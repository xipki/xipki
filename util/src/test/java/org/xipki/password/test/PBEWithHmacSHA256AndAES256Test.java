// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.password.PBEAlgo;
import org.xipki.password.PasswordBasedEncryption;
import org.xipki.util.StringUtil;

/**
 * Test for the algorithm PBEWithHmacSHA256AndAES256.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class PBEWithHmacSHA256AndAES256Test {

  private static PBEAlgo algo = PBEAlgo.PBEWithHmacSHA256AndAES_256;

  private static byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 15, 16};

  @Test
  public void encrypThenDecrypt() throws Exception {
    char[] password = "qwert".toCharArray();
    byte[] plainText = StringUtil.toUtf8Bytes("123456");
    int iterationCount = 1000;
    byte[] encrypted = PasswordBasedEncryption.encrypt(algo, plainText, password, iterationCount, salt);
    byte[] decrypted = PasswordBasedEncryption.decrypt(algo, encrypted, password, iterationCount, salt);
    Assert.assertArrayEquals(plainText, decrypted);
  }

  @Test
  public void decrypt() throws Exception {
    char[] password = "qwert".toCharArray();
    byte[] encrypted = new byte[]{16, // length of IV
      -15, -2, 113, -42, -46, 43, -65, -8, -51, 48, 6, 26, -73, -38, -111, -1, // IV
      75, 76, -36, -17, -96, -123, 2, -107, 92, -27, -114, -74, -80, 105, 46, 91};
    byte[] decrypted = PasswordBasedEncryption.decrypt(algo, encrypted, password, 1000, salt);
    Assert.assertArrayEquals(StringUtil.toUtf8Bytes("123456"), decrypted);
  }

}
