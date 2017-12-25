/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.server.impl.test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.ca.server.impl.util.PasswordHash;

/**
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
    public void testDuplication() throws NoSuchAlgorithmException, InvalidKeySpecException {
        Set<String> passwordHashes = new HashSet<>(20);
        for (int i = 0; i < 10; i++) {
            String passwordHash = PasswordHash.createHash("p\r\nassw0Rd!");
            Assert.assertFalse("PasswordHash duplication occurs",
                    passwordHashes.contains(passwordHash));
            passwordHashes.add(passwordHash);
        }
    }

    @Test
    public void testValidation() throws NoSuchAlgorithmException, InvalidKeySpecException {
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
