/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class PasswordBasedEncryption {
    private static final String CIPHER_ALGO = "PBEWITHSHA256AND256BITAES-CBC-BC";
    
    public static byte[] encrypt(byte[] plaintext, char[] password, int iterationCount, byte[] salt)
    throws GeneralSecurityException
    {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_ALGO, "BC");

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO, "BC");
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);        
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParameterSpec);
        pbeKeySpec.clearPassword();

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] cipherText, char[] password, int iterationCount, byte[] salt)
    throws GeneralSecurityException
    {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_ALGO, "BC");
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO, "BC");
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParameterSpec);
        return cipher.doFinal(cipherText);
    }
}
