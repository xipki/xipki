/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.xipki.util.Base64;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * PBE (Password Based Encrytion) password service.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class PBEPasswordService {

  public PBEPasswordService() {
  }

  public static char[] decryptPassword(char[] masterPassword, String passwordHint)
      throws PasswordResolverException {
    Args.notNull(masterPassword, "masterPassword");
    Args.notNull(passwordHint, "passwordHint");

    byte[] bytes = Base64.decode(passwordHint.substring("PBE:".length()));
    int len = bytes.length;
    if (len <= 16 && len != 0) {
      throw new PasswordResolverException("invalid length of the encrypted password");
    }

    int offset = 0;

    // PBE algorithm
    byte bb = bytes[offset++];
    int algoCode = (bb < 0) ? 256 + bb : bb;
    PBEAlgo algo = PBEAlgo.forCode(algoCode);
    if (algo == null) {
      throw new PasswordResolverException("unknown algorithm code " + algoCode);
    }

    // iteration count
    byte[] iterationCountBytes = Arrays.copyOfRange(bytes, offset, offset + 2);
    offset += 2;

    // salt
    byte[] salt = Arrays.copyOfRange(bytes, offset, offset + 16);
    offset += 16;

    // cipher text
    byte[] cipherText = Arrays.copyOfRange(bytes, offset, len);

    int iterationCount = new BigInteger(1, iterationCountBytes).intValue();
    byte[] pwd;
    try {
      pwd = PasswordBasedEncryption.decrypt(algo, cipherText, masterPassword, iterationCount, salt);
    } catch (GeneralSecurityException ex) {
      throw new PasswordResolverException("could not decrypt the password: " + ex.getMessage());
    }

    char[] ret = new char[pwd.length];
    for (int i = 0; i < pwd.length; i++) {
      ret[i] = (char) pwd[i];
    }

    return ret;
  } // method resolvePassword

  public static String encryptPassword(PBEAlgo algo, int iterationCount, char[] masterPassword,
      char[] password) throws PasswordResolverException {
    Args.range(iterationCount, "iterationCount", 1, 65535);
    Args.notNull(masterPassword, "masterPassword");
    Args.notNull(password, "password");

    byte[] iterationCountBytes = new byte[2];
    iterationCountBytes[0] = (byte) (iterationCount >>> 8);
    iterationCountBytes[1] = (byte) (iterationCount & 0xFF);

    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    byte[] encrypted;
    try {
      encrypted = PasswordBasedEncryption.encrypt(algo,
          StringUtil.toUtf8Bytes(new String(password)), masterPassword, iterationCount, salt);
    } catch (GeneralSecurityException ex) {
      throw new PasswordResolverException("could not encrypt the password: " + ex.getMessage());
    }

    byte[] encryptedText = new byte[1 + 2 + salt.length + encrypted.length];

    int offset = 0;

    // algo
    encryptedText[offset++] = (byte) (algo.code() & 0xFF);

    // iteration count
    System.arraycopy(iterationCountBytes, 0, encryptedText, offset, 2);
    offset += 2;

    // salt
    System.arraycopy(salt, 0, encryptedText, offset, salt.length);
    offset += salt.length;

    // cipher text
    System.arraycopy(encrypted, 0, encryptedText, offset, encrypted.length);
    return StringUtil.concat("PBE:", Base64.encodeToString(encryptedText));
  }

}
