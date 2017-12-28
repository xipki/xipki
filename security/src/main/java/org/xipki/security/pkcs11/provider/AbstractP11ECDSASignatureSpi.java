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
abstract class AbstractP11ECDSASignatureSpi extends SignatureSpi {

    private final HashAlgoType hashAlgo;

    private final boolean plain;

    private long mechanism;

    private OutputStream outputStream;

    private P11PrivateKey signingKey;

    /**
     *
     * @param hashAlgo
     *          hash algorithm. Could be {@code null}.
     */
    AbstractP11ECDSASignatureSpi(final HashAlgoType hashAlgo, final boolean plain) {
        this.hashAlgo = hashAlgo;
        this.plain = plain;
    }

    @Override
    protected void engineInitVerify(final PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("engineInitVerify unsupported");
    }

    @Override
    protected void engineInitSign(final PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof P11PrivateKey)) {
            throw new InvalidKeyException("privateKey is not instanceof "
                    + P11PrivateKey.class.getName());
        }
        String algo = privateKey.getAlgorithm();
        if (!("EC".equals(algo) || "ECDSA".equals(algo))) {
            throw new InvalidKeyException("privateKey is not an EC private key: " + algo);
        }

        this.signingKey = (P11PrivateKey) privateKey;
        if (signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA)) {
            mechanism = PKCS11Constants.CKM_ECDSA;
            if (hashAlgo == null) {
                outputStream = new ByteArrayOutputStream();
            } else {
                outputStream = new DigestOutputStream(hashAlgo.createDigest());
            }
        } else {
            if (hashAlgo == HashAlgoType.SHA1
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA1)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA1;
            } else if (hashAlgo == HashAlgoType.SHA224
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA224)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA224;
            } else if (hashAlgo == HashAlgoType.SHA256
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA256)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA256;
            } else if (hashAlgo == HashAlgoType.SHA384
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA384)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA384;
            } else if (hashAlgo == HashAlgoType.SHA512
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA512)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA512;
            } else if (hashAlgo == HashAlgoType.SHA3_224
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_224)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA3_224;
            } else if (hashAlgo == HashAlgoType.SHA3_256
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_256)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA3_256;
            } else if (hashAlgo == HashAlgoType.SHA3_384
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_384)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA3_384;
            } else if (hashAlgo == HashAlgoType.SHA3_512
                    && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_512)) {
                mechanism = PKCS11Constants.CKM_ECDSA_SHA3_512;
            } else {
                throw new InvalidKeyException("privateKey and algorithm does not match");
            }
            outputStream = new ByteArrayOutputStream();
        }

        this.signingKey = (P11PrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(final byte input) throws SignatureException {
        try {
            outputStream.write((int) input);
        } catch (IOException ex) {
            throw new SignatureException("IOException: " + ex.getMessage(), ex);
        }
    }

    @Override
    protected void engineUpdate(final byte[] input, final int off, final int len)
            throws SignatureException {
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
            return plain ? plainSignature : SignerUtil.dsaSigPlainToX962(plainSignature);
        } catch (XiSecurityException | P11TokenException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    @Override
    protected void engineSetParameter(final AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected void engineSetParameter(final String param, final Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected Object engineGetParameter(final String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected boolean engineVerify(final byte[] sigBytes) throws SignatureException {
        throw new UnsupportedOperationException("engineVerify unsupported");
    }

}
