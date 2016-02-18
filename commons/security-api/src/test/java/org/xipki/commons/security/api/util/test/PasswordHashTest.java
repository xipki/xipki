/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.security.api.util.test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xipki.commons.security.api.util.PasswordHash;

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
    public void testDuplication()
    throws NoSuchAlgorithmException, InvalidKeySpecException {
        Set<String> passwordHashes = new HashSet<>(20);
        for (int i = 0; i < 10; i++) {
            String passwordHash = PasswordHash.createHash("p\r\nassw0Rd!");
            Assert.assertFalse("PasswordHash duplication occurs",
                    passwordHashes.contains(passwordHash));
            passwordHashes.add(passwordHash);
        }
    }

    @Test
    public void testValidation()
    throws NoSuchAlgorithmException, InvalidKeySpecException {
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
