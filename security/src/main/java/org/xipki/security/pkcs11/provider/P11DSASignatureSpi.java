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

package org.xipki.security.pkcs11.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.xipki.security.HashAlgoType;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.DigestOutputStream;
import org.xipki.security.util.SignerUtil;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public abstract class P11DSASignatureSpi extends SignatureSpi {

    // CHECKSTYLE:SKIP
    public static class NONE extends P11DSASignatureSpi {

        public NONE() {
            super(null);
        }

    } // class NONE

    // CHECKSTYLE:SKIP
    public static class SHA1 extends P11DSASignatureSpi {

        public SHA1() {
            super(HashAlgoType.SHA1);
        }

    } // class SHA1

    // CHECKSTYLE:SKIP
    public static class SHA224 extends P11DSASignatureSpi {

        public SHA224() {
            super(HashAlgoType.SHA224);
        }

    } // class SHA224

    // CHECKSTYLE:SKIP
    public static class SHA256 extends P11DSASignatureSpi {

        public SHA256() {
            super(HashAlgoType.SHA256);
        }

    } // class SHA256

    // CHECKSTYLE:SKIP
    public static class SHA384 extends P11DSASignatureSpi {

        public SHA384() {
            super(HashAlgoType.SHA384);
        }

    } // class SHA384

    // CHECKSTYLE:SKIP
    public static class SHA512 extends P11DSASignatureSpi {

        public SHA512() {
            super(HashAlgoType.SHA512);
        }

    } // class SHA512

    // CHECKSTYLE:SKIP
    public static class SHA3_224 extends P11DSASignatureSpi {

        public SHA3_224() {
            super(HashAlgoType.SHA3_224);
        }

    }

    // CHECKSTYLE:SKIP
    public static class SHA3_256 extends P11DSASignatureSpi {

        public SHA3_256() {
            super(HashAlgoType.SHA3_256);
        }

    }

    // CHECKSTYLE:SKIP
    public static class SHA3_384 extends P11DSASignatureSpi {

        public SHA3_384() {
            super(HashAlgoType.SHA3_384);
        }

    }

    // CHECKSTYLE:SKIP
    public static class SHA3_512 extends P11DSASignatureSpi {

        public SHA3_512() {
            super(HashAlgoType.SHA3_512);
        }

    }

    private final HashAlgoType hashAlgo;

    private long mechanism;

    private OutputStream outputStream;

    private P11PrivateKey signingKey;

    private P11DSASignatureSpi(HashAlgoType hashAlgo) {
        this.hashAlgo = hashAlgo;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("engineInitVerify unsupported");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof P11PrivateKey)) {
            throw new InvalidKeyException("privateKey is not instanceof "
                    + P11PrivateKey.class.getName());
        }
        String algo = privateKey.getAlgorithm();
        if (!"DSA".equals(algo)) {
            throw new InvalidKeyException("privateKey is not a DSA private key: " + algo);
        }

        this.signingKey = (P11PrivateKey) privateKey;
        if (signingKey.supportsMechanism(PKCS11Constants.CKM_DSA)) {
            mechanism = PKCS11Constants.CKM_DSA;
            if (hashAlgo == null) {
                outputStream = new ByteArrayOutputStream();
            } else {
                outputStream = new DigestOutputStream(hashAlgo.createDigest());
            }
        } else {
            if (hashAlgo == HashAlgoType.SHA1
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA1)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA1;
            } else if (hashAlgo == HashAlgoType.SHA224
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA224)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA224;
            } else if (hashAlgo == HashAlgoType.SHA256
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA256)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA256;
            } else if (hashAlgo == HashAlgoType.SHA384
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA384)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA384;
            } else if (hashAlgo == HashAlgoType.SHA512
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA512)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA512;
            } else if (hashAlgo == HashAlgoType.SHA3_224
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_224)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA3_224;
            } else if (hashAlgo == HashAlgoType.SHA3_256
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_256)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA3_256;
            } else if (hashAlgo == HashAlgoType.SHA3_384
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_384)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA3_384;
            } else if (hashAlgo == HashAlgoType.SHA3_512
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_512)) {
                mechanism = PKCS11Constants.CKM_DSA_SHA3_512;
            } else {
                throw new InvalidKeyException("privateKey and algorithm does not match");
            }

            outputStream = new ByteArrayOutputStream();
        }

        this.signingKey = (P11PrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte input) throws SignatureException {
        try {
            outputStream.write((int) input);
        } catch (IOException ex) {
            throw new SignatureException("IOException: " + ex.getMessage(), ex);
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int off, int len) throws SignatureException {
        try {
            outputStream.write(input, off, len);
        } catch (IOException ex) {
            throw new SignatureException("IOException: " + ex.getMessage(), ex);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
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
            return SignerUtil.dsaSigPlainToX962(plainSignature);
        } catch (P11TokenException | XiSecurityException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new UnsupportedOperationException("engineVerify unsupported");
    }

}
