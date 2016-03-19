/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.security.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.Nullable;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.util.SignerUtil;
import org.xipki.commons.security.impl.p11.DigestOutputStream;
import org.xipki.commons.security.impl.util.SecurityUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
abstract class P11DSASignatureSpi extends SignatureSpi {

    // CHECKSTYLE:SKIP
    static class SHA1 extends P11DSASignatureSpi {

        SHA1() {
            super(HashAlgoType.SHA1);
        }

    } // class SHA1

    // CHECKSTYLE:SKIP
    static class NONE extends P11DSASignatureSpi {

        NONE() {
            super(null);
        }

    } // class NONE

    // CHECKSTYLE:SKIP
    static class SHA224 extends P11DSASignatureSpi {

        SHA224() {
            super(HashAlgoType.SHA224);
        }

    } // class SHA224

    // CHECKSTYLE:SKIP
    static class SHA256 extends P11DSASignatureSpi {

        SHA256() {
            super(HashAlgoType.SHA256);
        }

    } // class SHA256

    // CHECKSTYLE:SKIP
    static class SHA384 extends P11DSASignatureSpi {

        SHA384() {
            super(HashAlgoType.SHA384);
        }

    } // class SHA384

    // CHECKSTYLE:SKIP
    static class SHA512 extends P11DSASignatureSpi {

        SHA512() {
            super(HashAlgoType.SHA512);
        }

    } // class SHA512

    private final HashAlgoType hashAlgo;

    private long mechanism;

    private OutputStream outputStream;

    private P11PrivateKey signingKey;

    P11DSASignatureSpi(
            @Nullable final HashAlgoType hashAlgo) {
        this.hashAlgo = ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    }

    @Override
    protected void engineInitVerify(
            final PublicKey publicKey)
    throws InvalidKeyException {
        throw new UnsupportedOperationException("engineInitVerify unsupported");
    }

    @Override
    protected void engineInitSign(
            final PrivateKey privateKey)
    throws InvalidKeyException {
        if (!(privateKey instanceof P11PrivateKey)) {
            throw new InvalidKeyException("privateKey is not instanceof "
                    + P11PrivateKey.class.getName());
        }
        String algo = privateKey.getAlgorithm();
        if (!"DSA".equals(algo)) {
            throw new InvalidKeyException("privateKey is not a DSA private key: " + algo);
        }

        this.signingKey = (P11PrivateKey) privateKey;
        if (signingKey.supportsMechanism(P11Constants.CKM_DSA)) {
            mechanism = P11Constants.CKM_DSA;
            if (hashAlgo == null) {
                outputStream = new ByteArrayOutputStream();
            } else {
                outputStream = SecurityUtil.getDigestOutputStream(hashAlgo);
            }
        } else {
            if (hashAlgo == HashAlgoType.SHA1
                    && signingKey.supportsMechanism(P11Constants.CKM_DSA_SHA1)) {
                mechanism = P11Constants.CKM_DSA_SHA1;
            } else if (hashAlgo == HashAlgoType.SHA224
                    && signingKey.supportsMechanism(P11Constants.CKM_DSA_SHA224)) {
                mechanism = P11Constants.CKM_DSA_SHA224;
            } else if (hashAlgo == HashAlgoType.SHA256
                    && signingKey.supportsMechanism(P11Constants.CKM_DSA_SHA256)) {
                mechanism = P11Constants.CKM_DSA_SHA256;
            } else if (hashAlgo == HashAlgoType.SHA384
                    && signingKey.supportsMechanism(P11Constants.CKM_DSA_SHA384)) {
                mechanism = P11Constants.CKM_DSA_SHA384;
            } else if (hashAlgo == HashAlgoType.SHA512
                    && signingKey.supportsMechanism(P11Constants.CKM_DSA_SHA512)) {
                mechanism = P11Constants.CKM_DSA_SHA512;
            } else {
                throw new InvalidKeyException("privateKey and algorithm does not match");
            }

            outputStream = new ByteArrayOutputStream();
        }

        this.signingKey = (P11PrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(
            final byte input)
    throws SignatureException {
        try {
            outputStream.write((int) input);
        } catch (IOException ex) {
            throw new SignatureException("IOException: " + ex.getMessage(), ex);
        }
    }

    @Override
    protected void engineUpdate(
            final byte[] input,
            final int off,
            final int len)
    throws SignatureException {
        try {
            outputStream.write(input, off, len);
        } catch (IOException ex) {
            throw new SignatureException("IOException: " + ex.getMessage(), ex);
        }
    }

    @Override
    protected byte[] engineSign()
    throws SignatureException {
        byte[] dataToSign;
        if (outputStream instanceof ByteArrayOutputStream) {
            dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
            ((ByteArrayOutputStream) outputStream).reset();
        } else {
            dataToSign = ((DigestOutputStream) outputStream).digest();
            ((DigestOutputStream) outputStream).reset();
        }

        try {
            byte[] plainSignature = signingKey.sign(mechanism, null, dataToSign);
            return SignerUtil.convertPlainDSASigToX962(plainSignature);
        } catch (P11TokenException | SecurityException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    @Override
    protected void engineSetParameter(
            final AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected void engineSetParameter(
            final String param,
            final Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected Object engineGetParameter(
            final String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected boolean engineVerify(
            final byte[] sigBytes)
    throws SignatureException {
        throw new UnsupportedOperationException("engineVerify unsupported");
    }

}
