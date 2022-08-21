/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.password;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.GeneralSecurityException;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

/**
 * Password based encryption utility class.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PasswordBasedEncryption {

  private PasswordBasedEncryption() {
  }

  /**
   * Encrypts the message using password based encryption.
   * @param algo
   *        the encryption algorithm
   * @param plaintext
   *        the message to be encrypted
   * @param password
   *        the password
   * @param iterationCount
   *        the iteration count
   * @param salt
   *        the salt
   * @return iv and the cipher text in form of
   *         len(iv) of 1 byte | iv of len(iv) bytes | cipher text.
   * @throws GeneralSecurityException
   *         if error occurs.
   */
  public static byte[] encrypt(PBEAlgo algo, byte[] plaintext, char[] password, int iterationCount, byte[] salt)
      throws GeneralSecurityException {
    notNull(plaintext, "plaintext");
    notNull(password, "password");
    positive(iterationCount, "iterationCount");
    notNull(salt, "salt");

    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo.algoName());

    PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
    SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

    Cipher cipher = Cipher.getInstance(algo.algoName());
    PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
    cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParameterSpec);
    pbeKeySpec.clearPassword();

    byte[] iv = cipher.getIV();
    int ivLen = (iv == null) ? 0 : iv.length;
    if (ivLen > 255) {
      throw new GeneralSecurityException("IV too long: " + ivLen);
    }

    byte[] cipherText = cipher.doFinal(plaintext);
    byte[] ret = new byte[1 + ivLen + cipherText.length];
    // length of IV
    ret[0] = (byte) (ivLen & 0xFF);
    if (ivLen > 0) {
      System.arraycopy(iv, 0, ret, 1, ivLen);
    }

    System.arraycopy(cipherText, 0, ret, 1 + ivLen, cipherText.length);
    return ret;
  } // method encrypt

  public static byte[] decrypt(PBEAlgo algo, byte[] cipherTextWithIv, char[] password, int iterationCount, byte[] salt)
      throws GeneralSecurityException {
    notNull(cipherTextWithIv, "cipherTextWithIv");
    notNull(password, "password");
    positive(iterationCount, "iterationCount");
    notNull(salt, "salt");

    PBEKeySpec pbeKeySpec = new PBEKeySpec(password);

    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo.algoName());
    SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

    Cipher cipher = Cipher.getInstance(algo.algoName());

    // extract the IV and cipherText
    byte bb = cipherTextWithIv[0];
    int ivLen = (bb < 0) ? 256 + bb : bb;

    PBEParameterSpec pbeParameterSpec;
    if (ivLen == 0) {
      pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
    } else {
      byte[] iv = new byte[ivLen];
      System.arraycopy(cipherTextWithIv, 1, iv, 0, ivLen);
      pbeParameterSpec = new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(iv));
    }

    int cipherTextOffset = 1 + ivLen;
    byte[] cipherText = new byte[cipherTextWithIv.length - cipherTextOffset];
    System.arraycopy(cipherTextWithIv, 1 + ivLen, cipherText, 0, cipherText.length);

    cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParameterSpec);
    return cipher.doFinal(cipherText);
  } // method decrypt

}
