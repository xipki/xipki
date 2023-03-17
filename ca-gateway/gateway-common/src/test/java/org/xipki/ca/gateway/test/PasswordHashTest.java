// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.ca.gateway.PasswordHash;

import java.security.Security;
import java.util.HashSet;
import java.util.Set;

/**
 * PasswordHash test.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PasswordHashTest {

  @Before
  public void addBouncyCastleProvider() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void testDuplication() {
    Set<String> passwordHashes = new HashSet<>(20);
    for (int i = 0; i < 10; i++) {
      String passwordHash = PasswordHash.createHash("p\r\nassw0Rd!");
      Assert.assertFalse("PasswordHash duplication occurs", passwordHashes.contains(passwordHash));
      passwordHashes.add(passwordHash);
    }
  }

  @Test
  public void testValidation() {
    boolean failure = false;
    for (int i = 0; i < 100; i++) {
      String password = "" + i;
      String hash = PasswordHash.createHash(password);

      String wrongPassword = "" + (i + 1);
      if (PasswordHash.validatePassword(wrongPassword, hash)) {
        System.out.println("FAILURE: WRONG PASSWORD ACCEPTED!");
        failure = true;
      }
      if (!PasswordHash.validatePassword(password, hash)) {
        System.out.println("FAILURE: GOOD PASSWORD NOT ACCEPTED!");
        failure = true;
      }
    }

    Assert.assertFalse("test validation failed", failure);
  }

}
