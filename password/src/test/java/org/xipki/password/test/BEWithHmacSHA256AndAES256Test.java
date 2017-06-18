package org.xipki.password.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.password.PBEAlgo;
import org.xipki.password.PasswordBasedEncryption;

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
