// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.GeneralSecurityException;

/**
 * Password based encryption utility class.
 *
 * @author Lijun Liao (xipki)
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
    Args.notNull(plaintext, "plaintext");
    Args.notNull(password, "password");
    Args.positive(iterationCount, "iterationCount");
    Args.notNull(salt, "salt");

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
    Args.notNull(cipherTextWithIv, "cipherTextWithIv");
    Args.notNull(password, "password");
    Args. positive(iterationCount, "iterationCount");
    Args. notNull(salt, "salt");

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
