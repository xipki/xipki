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

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PasswordBasedEncryption {

    private PasswordBasedEncryption() {
    }

    /**
     *
     * @return iv and the cipher text in form of
     *           len(iv) of 1 byte | iv of len(iv) bytes | cipher text.
     */
    public static byte[] encrypt(final PBEAlgo algo, byte[] plaintext, final char[] password,
            final int iterationCount, final byte[] salt) throws GeneralSecurityException {
        ParamUtil.requireNonNull("plaintext", plaintext);
        ParamUtil.requireNonNull("password", password);
        ParamUtil.requireMin("iterationCount", iterationCount, 1);
        ParamUtil.requireNonNull("salt", salt);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo.algoName());

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(algo.algoName());
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParameterSpec);
        pbeKeySpec.clearPassword();

        byte[] iv = cipher.getIV();
        int ivLen = (iv == null) ? 0 : iv.length;
        if (ivLen > 255) {
            throw new GeneralSecurityException("IV too long: " + ivLen);
        }

        byte[] cipherText = cipher.doFinal(plaintext);
        byte[] ret = new byte[1 + ivLen + cipherText.length];
        // length of IV
        ret[0] = (byte) (ivLen & 0xFF);
        if (ivLen > 0) {
            System.arraycopy(iv, 0, ret, 1, ivLen);
        }

        System.arraycopy(cipherText, 0, ret, 1 + ivLen, cipherText.length);
        return ret;
    }

    public static byte[] decrypt(final PBEAlgo algo, final byte[] cipherTextWithIv,
            final char[] password, final int iterationCount, final byte[] salt)
            throws GeneralSecurityException {
        ParamUtil.requireNonNull("cipherTextWithIv", cipherTextWithIv);
        ParamUtil.requireNonNull("password", password);
        ParamUtil.requireMin("iterationCount", iterationCount, 1);
        ParamUtil.requireNonNull("salt", salt);

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo.algoName());
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(algo.algoName());

        // extract the IV and cipherText
        byte bb = cipherTextWithIv[0];
        int ivLen = (bb < 0) ? 256 + bb : bb;

        PBEParameterSpec pbeParameterSpec;
        if (ivLen == 0) {
            pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        } else {
            byte[] iv = new byte[ivLen];
            System.arraycopy(cipherTextWithIv, 1, iv, 0, ivLen);
            pbeParameterSpec = new PBEParameterSpec(salt, iterationCount,
                    new IvParameterSpec(iv));
        }

        int cipherTextOffset = 1 + ivLen;
        byte[] cipherText = new byte[cipherTextWithIv.length - cipherTextOffset];
        System.arraycopy(cipherTextWithIv, 1 + ivLen, cipherText, 0, cipherText.length);

        cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParameterSpec);
        return cipher.doFinal(cipherText);
    }

}
