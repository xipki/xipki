/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Lijun Liao
 */

public class PasswordBasedEncryption {

    private static final String CIPHER_ALGO = "PBEWITHSHA256AND256BITAES-CBC-BC";

    private static AtomicBoolean initialized = new AtomicBoolean(false);

    private PasswordBasedEncryption() {
    }

    private static void init() {
        synchronized (initialized) {
            if (initialized.get()) {
                return;
            }

            if (Security.getProperty("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            initialized.set(true);
        }
    }

    public static byte[] encrypt(
            final byte[] plaintext,
            final char[] password,
            final int iterationCount,
            final byte[] salt)
    throws GeneralSecurityException {
        init();
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_ALGO, "BC");

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO, "BC");
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParameterSpec);
        pbeKeySpec.clearPassword();

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(
            final byte[] cipherText,
            final char[] password,
            final int iterationCount,
            byte[] salt)
    throws GeneralSecurityException {
        init();
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_ALGO, "BC");
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO, "BC");
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParameterSpec);
        return cipher.doFinal(cipherText);
    }

}
