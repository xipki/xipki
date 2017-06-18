/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.password;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class PBEPasswordService {

    public PBEPasswordService() {
    }

    public static char[] decryptPassword(final char[] masterPassword, final String passwordHint)
            throws PasswordResolverException {
        ParamUtil.requireNonNull("masterPassword", masterPassword);
        ParamUtil.requireNonNull("passwordHint", passwordHint);

        byte[] bytes = Base64.getDecoder().decode(passwordHint.substring("PBE:".length()));
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
            pwd = PasswordBasedEncryption.decrypt(algo, cipherText, masterPassword,
                    iterationCount, salt);
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

    public static String encryptPassword(final PBEAlgo algo,
            final int iterationCount, final char[] masterPassword,
            final char[] password) throws PasswordResolverException {
        ParamUtil.requireRange("iterationCount", iterationCount, 1, 65535);
        ParamUtil.requireNonNull("masterPassword", masterPassword);
        ParamUtil.requireNonNull("password", password);

        byte[] iterationCountBytes = new byte[2];
        iterationCountBytes[0] = (byte) (iterationCount >>> 8);
        iterationCountBytes[1] = (byte) (iterationCount & 0xFF);

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        byte[] encrypted;
        try {
            encrypted = PasswordBasedEncryption.encrypt(algo, new String(password).getBytes(),
                    masterPassword, iterationCount, salt);
        } catch (GeneralSecurityException ex) {
            throw new PasswordResolverException("could not encrypt the password: "
                    + ex.getMessage());
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
        return "PBE:" + Base64.getEncoder().encodeToString(encryptedText);
    }

}
