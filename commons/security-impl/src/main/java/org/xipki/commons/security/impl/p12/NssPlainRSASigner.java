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

package org.xipki.commons.security.impl.p12;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class NssPlainRSASigner implements AsymmetricBlockCipher {

    private static final String ALGORITHM = "RSA/ECB/NoPadding";

    private final KeyFactory rsaKeyFactory;
    private Cipher cipher;

    private RSAKeyParameters key;

    NssPlainRSASigner()
    throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        cipher = Cipher.getInstance(ALGORITHM, "SunPKCS11-XipkiNSS");
        rsaKeyFactory = KeyFactory.getInstance("RSA");
    }

    @Override
    public void init(
            final boolean forEncryption,
            final CipherParameters param) {
        if (!forEncryption) {
            throw new RuntimeCryptoException("verification mode not supported.");
        }

        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;

            key = (RSAKeyParameters) rParam.getParameters();
        } else {
            key = (RSAKeyParameters) param;
        }

        RSAPrivateKeySpec keySpec = null;
        if (key instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters params = (RSAPrivateCrtKeyParameters) key;
            keySpec = new RSAPrivateCrtKeySpec(params.getModulus(), // modulus
                    params.getPublicExponent(), // publicExponent
                    params.getModulus(), // privateExponent
                    params.getP(), // primeP
                    params.getQ(), // primeQ
                    params.getDP(), // primeExponentP
                    params.getDQ(), // primeExponentQ
                    params.getQInv());// crtCoefficient
        } else {
            RSAKeyParameters params = (RSAKeyParameters) key;
            keySpec = new RSAPrivateKeySpec(params.getModulus(), params.getExponent());
        }
        RSAPrivateKey signingKey;
        try {
            signingKey = (RSAPrivateKey) rsaKeyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException ex) {
            throw new RuntimeCryptoException("could not generate RSA private key from param: "
                    + ex.getMessage());
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, signingKey);
        } catch (InvalidKeyException ex) {
            throw new RuntimeCryptoException("could not initialize the cipher: "
                    + ex.getMessage());
        }
    }

    @Override
    public int getInputBlockSize() {
        return (key.getModulus().bitLength() + 7) / 8;
    }

    @Override
    public int getOutputBlockSize() {
        return (key.getModulus().bitLength() + 7) / 8;
    }

    @Override
    public byte[] processBlock(
            final byte[] in,
            final int inOff,
            final int len)
    throws InvalidCipherTextException {
        try {
            return cipher.doFinal(in, 0, in.length);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new InvalidCipherTextException(ex.getMessage(), ex);
        }
    }

} // class NssPlainRSASigner

