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

package org.xipki.ca.server.impl.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.xipki.common.util.ParamUtil;

/**
 * PBKDF2 salted password hashing.
 * @author: havoc AT defuse.ca, www: http://crackstation.net/hashing-security.htm
 */
public class PasswordHash {

    // see 'http://stackoverflow.com/questions/22580853/reliable-implementation-of-pbkdf2-hmac-sha256-for-java'
    // public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";

    // The following constants may be changed without breaking existing hashes.
    public static final int SALT_BYTE_SIZE = 24;
    public static final int DERIVED_KEY_SIZE = 32;
    public static final int PBKDF2_ITERATIONS = 1000;

    public static final int ITERATION_INDEX = 0;
    public static final int SALT_INDEX = 1;
    public static final int PBKDF2_INDEX = 2;

    private static final PKCS5S2ParametersGenerator GEN;

    static {
        GEN = new PKCS5S2ParametersGenerator(new SHA256Digest());
    }

    private PasswordHash() {
    }

    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param password - the password to hash
     * @return a salted PBKDF2 hash of the password
     */
    public static String createHash(final String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParamUtil.requireNonBlank("password", password);
        return createHash(password.getBytes());
    }

    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param password - the password to hash
     * @return a salted PBKDF2 hash of the password
     */
    public static String createHash(final byte[] password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return createHash(password, SALT_BYTE_SIZE, PBKDF2_ITERATIONS, DERIVED_KEY_SIZE);
    }

    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param password - the password to hash
     * @return a salted PBKDF2 hash of the password
     */
    public static String createHash(final byte[] password, final int saltSize, final int iterations,
            final int dkSize) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParamUtil.requireNonNull("password", password);
        // Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[saltSize];
        random.nextBytes(salt);

        // Hash the password
        byte[] hash = pbkdf2(password, salt, iterations, dkSize);
        // format iterations:salt:hash
        return iterations + ":" + toHex(salt) + ":" + toHex(hash);
    }

    /**
     * Validates a password using a hash.
     *
     * @param password - the password to check
     * @param correctHash - the hash of the valid password
     * @return true if the password is correct, false if not
     */
    public static boolean validatePassword(final String password, final String correctHash)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParamUtil.requireNonBlank("password", password);
        return validatePassword(password.getBytes(), correctHash);
    }

    /**
     * Validates a password using a hash.
     *
     * @param password - the password to check
     * @param correctHash - the hash of the valid password
     * @return true if the password is correct, false if not
     */
    public static boolean validatePassword(final byte[] password, final String correctHash)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParamUtil.requireNonNull("password", password);
        // Decode the hash into its parameters
        String[] params = correctHash.split(":");
        int iterations = Integer.parseInt(params[ITERATION_INDEX]);
        byte[] salt = fromHex(params[SALT_INDEX]);
        byte[] hash = fromHex(params[PBKDF2_INDEX]);
        // Compute the hash of the provided password, using the same salt,
        // iteration count, and hash length
        byte[] testHash = pbkdf2(password, salt, iterations, hash.length);
        // Compare the hashes in constant time. The password is correct if
        // both hashes match.
        return slowEquals(hash, testHash);
    }

    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     *
     * @param arrayA - the first byte array
     * @param arrayB - the second byte array
     * @return true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(final byte[] arrayA, final byte[] arrayB) {
        int diff = arrayA.length ^ arrayB.length;
        for (int i = 0; i < arrayA.length && i < arrayB.length; i++) {
            diff |= arrayA[i] ^ arrayB[i];
        }
        return diff == 0;
    }

    /**
     * Computes the PBKDF2 hash of a password.
     *
     * @param password - the password to hash.
     * @param salt - the salt
     * @param iterations - the iteration count (slowness factor)
     * @param bytes - the length of the hash to compute in bytes
     * @return the PBDKF2 hash of the password
     */
    public static byte[] pbkdf2(final byte[] password, final byte[] salt, final int iterations,
            final int bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] pwdBytes;
        try {
            pwdBytes = new String(password).getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new NoSuchAlgorithmException("no charset UTF-8");
        }
        synchronized (GEN) {
            GEN.init(pwdBytes, salt, iterations);
            byte[] dk = ((KeyParameter) GEN.generateDerivedParameters(bytes * 8)).getKey();
            return dk;
        }
    }

    /**
     * Converts a string of hexadecimal characters into a byte array.
     *
     * @param hex - the hex string
     * @return the hex string decoded into a byte array
     */
    private static byte[] fromHex(final String hex) {
        byte[] binary = new byte[hex.length() / 2];
        for (int i = 0; i < binary.length; i++) {
            binary[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return binary;
    }

    /**
     * Converts a byte array into a hexadecimal string.
     *
     * @param array - the byte array to convert
     * @return a length*2 character string encoding the byte array
     */
    private static String toHex(final byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        return (paddingLength > 0) ? String.format("%0" + paddingLength + "d", 0) + hex : hex;
    }

}
