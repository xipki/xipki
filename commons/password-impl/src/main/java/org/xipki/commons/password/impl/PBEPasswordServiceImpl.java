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

package org.xipki.commons.password.impl;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.xipki.commons.password.api.PBEPasswordService;
import org.xipki.commons.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PBEPasswordServiceImpl implements PBEPasswordService {

    public PBEPasswordServiceImpl() {
    }

    public static char[] doDecryptPassword(
            final char[] masterPassword,
            final String passwordHint)
    throws PasswordResolverException {
        byte[] bytes = Base64.getDecoder().decode(passwordHint.substring("PBE:".length()));
        int n = bytes.length;
        if (n <= 16 && n != 0) {
            throw new PasswordResolverException("invalid length of the encrypted password");
        }

        byte[] iterationCounntBytes = Arrays.copyOfRange(bytes, 0, 2);
        byte[] salt = Arrays.copyOfRange(bytes, 2, 18);
        byte[] cipherText = Arrays.copyOfRange(bytes, 18, n);

        int iterationCount = new BigInteger(1, iterationCounntBytes).intValue();
        byte[] pwd;
        try {
            pwd = PasswordBasedEncryption.decrypt(cipherText, masterPassword, iterationCount,
                    salt);
        } catch (GeneralSecurityException ex) {
            throw new PasswordResolverException("could not decrypt the password: "
                    + ex.getMessage());
        }

        char[] ret = new char[pwd.length];
        for (int i = 0; i < pwd.length; i++) {
            ret[i] = (char) pwd[i];
        }

        return ret;
    } // method resolvePassword

    public static String doEncryptPassword(
            final int iterationCount,
            final char[] masterPassword,
            final char[] password)
    throws PasswordResolverException {
        if (iterationCount < 1 | iterationCount > 65535) {
            throw new IllegalArgumentException("iterationCount is not between 1 and 65535");
        }
        byte[] iterationCountBytes = new byte[2];
        iterationCountBytes[0] = (byte) (iterationCount >>> 8);
        iterationCountBytes[1] = (byte) (iterationCount & 0xFF);

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        byte[] encrypted;
        try {
            encrypted = PasswordBasedEncryption.encrypt(new String(password).getBytes(),
                    masterPassword, iterationCount, salt);
        } catch (GeneralSecurityException ex) {
            throw new PasswordResolverException("could not encrypt the password: "
                    + ex.getMessage());
        }

        byte[] encryptedWithSalt = new byte[2 + salt.length + encrypted.length];
        System.arraycopy(salt, 0, iterationCountBytes, 0, 2);
        System.arraycopy(salt, 0, encryptedWithSalt, 2, salt.length);
        System.arraycopy(encrypted, 0, encryptedWithSalt, 2 + salt.length, encrypted.length);
        String pbeText = "PBE:" + Base64.getEncoder().encodeToString(encryptedWithSalt);
        return pbeText;
    }

    @Override
    public char[] decryptPassword(
            final char[] masterPassword,
            final String passwordHint)
    throws PasswordResolverException {
        return doDecryptPassword(masterPassword, passwordHint);
    }

    @Override
    public String encryptPassword(
            final int iterationCount,
            final char[] masterPassword,
            final char[] password)
    throws PasswordResolverException {
        return doEncryptPassword(iterationCount, masterPassword, password);
    }

}
