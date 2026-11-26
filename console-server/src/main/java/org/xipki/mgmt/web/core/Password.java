// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.mindrot.jbcrypt.BCrypt;

/**
 * New passwords use JDK PBKDF2; bounded BCrypt verification preserves existing accounts.
 *
 * @author palos
 */
public final class Password {
  private static final int ITERATIONS = 600_000;
  private static final String PREFIX = "$pbkdf2-sha256$";
  private final SecureRandom random = new SecureRandom();

  public String encode(CharSequence password) {
    validate(password);
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    byte[] hash = derive(password, salt, ITERATIONS);
    try {
      return PREFIX
          + ITERATIONS
          + "$"
          + Base64.getEncoder().withoutPadding().encodeToString(salt)
          + "$"
          + Base64.getEncoder().withoutPadding().encodeToString(hash);
    } finally {
      Arrays.fill(hash, (byte) 0);
    }
  }

  public boolean needsUpgrade(String hash) {
    return hash != null && hash.matches("\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}");
  }

  public boolean matches(CharSequence password, String hash) {
    try {
      validate(password);
      if (hash == null || hash.length() > 200) {
        return false;
      }
      if (needsUpgrade(hash)) {
        int cost = Integer.parseInt(hash.substring(4, 6));
        if (cost < 4 || cost > 14) {
          return false;
        }
        return BCrypt.checkpw(password.toString(), "$2a$" + hash.substring(4));
      }
      if (!hash.startsWith(PREFIX)) {
        return false;
      }
      String[] fields = hash.substring(PREFIX.length()).split("\\$", -1);
      if (fields.length != 3
          || !fields[0].matches("[0-9]{1,7}")
          || fields[1].length() != 22
          || fields[2].length() != 43) {
        return false;
      }
      int iterations = Integer.parseInt(fields[0]);
      if (iterations < ITERATIONS || iterations > 1_200_000) {
        return false;
      }
      byte[] salt = Base64.getDecoder().decode(fields[1]),
          expected = Base64.getDecoder().decode(fields[2]);
      if (salt.length != 16 || expected.length != 32) {
        return false;
      }
      byte[] actual = derive(password, salt, iterations);
      try {
        return MessageDigest.isEqual(expected, actual);
      } finally {
        Arrays.fill(actual, (byte) 0);
      }
    } catch (IllegalArgumentException ex) {
      return false;
    }
  }

  private static byte[] derive(CharSequence value, byte[] salt, int iterations) {
    char[] chars = value.toString().toCharArray();
    PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256);
    Arrays.fill(chars, '\0');
    try {
      return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("PBKDF2 unavailable", ex);
    } finally {
      spec.clearPassword();
    }
  }

  private static void validate(CharSequence value) {
    if (value == null
        || value.toString().getBytes(StandardCharsets.UTF_8).length > 72
        || value.toString().indexOf('\0') >= 0) {
      throw new IllegalArgumentException("Invalid password length or character");
    }
  }
}
