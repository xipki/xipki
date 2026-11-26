// License Apache License 2.0

package org.xipki.mgmt.web.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * @author palos
 */
class PasswordTest {
  @Test
  void acceptsExistingBcrypt2aHashes() {
    // Standard BCrypt fixture; the existing backend also writes $2a$ hashes.
    Password passwords = new Password();
    String hash = "$2a$10$......................7zqaLmaKtn.i7IjPfuPGY2Ah/mNM6Sy";
    assertTrue(passwords.matches("password", hash));
    assertFalse(passwords.matches("incorrect", hash));
    assertFalse(passwords.matches("anything", "broken-hash"));
  }

  @Test
  void rejectsUnboundedOrMalformedWorkFactors() {
    Password passwords = new Password();
    assertFalse(
        passwords.matches(
            "password", "$2a$31$......................7zqaLmaKtn.i7IjPfuPGY2Ah/mNM6Sy"));
    assertFalse(passwords.matches("password", "$pbkdf2-sha256$9999999999$a$b"));
  }

  @Test
  void generatesDistinctHashesAndEnforcesBcryptByteLimit() {
    Password passwords = new Password();
    String hash = passwords.encode("密碼-Example123!");
    assertTrue(hash.startsWith("$pbkdf2-sha256$"));
    assertTrue(passwords.matches("密碼-Example123!", hash));
    assertNotEquals(hash, passwords.encode("密碼-Example123!"));
    assertThrows(IllegalArgumentException.class, () -> passwords.encode("中".repeat(25)));
    assertFalse(passwords.matches("中".repeat(25), hash));
  }
}
