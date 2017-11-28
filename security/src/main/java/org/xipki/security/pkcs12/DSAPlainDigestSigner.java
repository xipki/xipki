/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.security.pkcs12;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.SignerUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class DSAPlainDigestSigner implements Signer {

    private final Digest digest;

    private final DSA dsaSigner;

    private boolean forSigning;

    private int keyBitLen;

    public DSAPlainDigestSigner(final DSA signer, final Digest digest) {
        this.digest = digest;
        this.dsaSigner = signer;
    }

    @Override
    public void init(final boolean forSigning, final CipherParameters parameters) {
        this.forSigning = forSigning;

        AsymmetricKeyParameter param;

        if (parameters instanceof ParametersWithRandom) {
            param = (AsymmetricKeyParameter) ((ParametersWithRandom) parameters).getParameters();
        } else {
            param = (AsymmetricKeyParameter) parameters;
        }

        ParamUtil.requireNonNull("param", param);
        if (param instanceof ECPublicKeyParameters) {
            keyBitLen = ((ECPublicKeyParameters) param).getParameters().getCurve().getFieldSize();
        } else if (param instanceof ECPrivateKeyParameters) {
            keyBitLen = ((ECPrivateKeyParameters) param).getParameters().getCurve().getFieldSize();
        } else if (param instanceof DSAPublicKeyParameters) {
            keyBitLen = ((DSAPublicKeyParameters) param).getParameters().getQ().bitLength();
        } else if (param instanceof DSAPrivateKeyParameters) {
            keyBitLen = ((DSAPrivateKeyParameters) param).getParameters().getQ().bitLength();
        } else {
            throw new IllegalArgumentException("unknown parameters: " + param.getClass().getName());
        }

        if (forSigning && !param.isPrivate()) {
            throw new IllegalArgumentException("Signing Requires Private Key.");
        }

        if (!forSigning && param.isPrivate()) {
            throw new IllegalArgumentException("Verification Requires Public Key.");
        }

        reset();

        dsaSigner.init(forSigning, parameters);
    }

    @Override
    public void update(final byte input) {
        digest.update(input);
    }

    @Override
    public void update(final byte[] input, final int inOff, final int length) {
        digest.update(input, inOff, length);
    }

    @Override
    public byte[] generateSignature() {
        if (!forSigning) {
            throw new IllegalStateException(
                    "DSADigestSigner not initialized for signature generation.");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        BigInteger[] sig = dsaSigner.generateSignature(hash);

        try {
            return SignerUtil.convertDSASigToPlain(sig[0], sig[1], keyBitLen);
        } catch (XiSecurityException ex) {
            throw new IllegalStateException("unable to encode signature");
        }
    }

    @Override
    public boolean verifySignature(final byte[] signature) {
        if (forSigning) {
            throw new IllegalStateException("DSADigestSigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try {
            BigInteger[] sig = decode(signature);
            return dsaSigner.verifySignature(hash, sig[0], sig[1]);
        } catch (IOException ex) {
            return false;
        }
    }

    @Override
    public void reset() {
        digest.reset();
    }

    private BigInteger[] decode(final byte[] encoding) throws IOException {
        int blockSize = (keyBitLen + 7) / 8;
        if (encoding.length != 2 * blockSize) {
            throw new IOException("invalid length of signature");
        }

        BigInteger[] ret = new BigInteger[2];
        byte[] buffer = new byte[blockSize + 1];
        System.arraycopy(encoding, 0, buffer, 1, blockSize);
        ret[0] = new BigInteger(buffer);

        buffer = new byte[blockSize + 1];
        System.arraycopy(encoding, blockSize, buffer, 1, blockSize);
        ret[1] = new BigInteger(buffer);
        return ret;
    }

}
