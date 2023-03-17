// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import org.xipki.util.Base64;
import org.xipki.util.RandomUtil;
import org.xipki.util.StringUtil;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.range;

/**
 * PBE (Password Based Encryption) password service.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
public class PBEPasswordService {

  public static final String PROTOCOL_PBE = "PBE";

  public PBEPasswordService() {
  }

  public static char[] decryptPassword(char[] masterPassword, String passwordHint)
      throws PasswordResolverException {
    notNull(masterPassword, "masterPassword");
    notNull(passwordHint, "passwordHint");

    byte[] bytes = Base64.decode(passwordHint.substring(PROTOCOL_PBE.length() + 1));
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
  } // method decryptPassword

  public static String encryptPassword(PBEAlgo algo, int iterationCount, char[] masterPassword, char[] password)
      throws PasswordResolverException {
    range(iterationCount, "iterationCount", 1, 65535);
    notNull(masterPassword, "masterPassword");
    notNull(password, "password");

    byte[] iterationCountBytes = new byte[2];
    iterationCountBytes[0] = (byte) (iterationCount >>> 8);
    iterationCountBytes[1] = (byte) (iterationCount & 0xFF);

    byte[] salt = RandomUtil.nextBytes(16);
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
    return StringUtil.concat(PROTOCOL_PBE, ":", Base64.encodeToString(encryptedText));
  } // method encryptPassword

}
