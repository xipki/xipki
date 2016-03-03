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
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class DSAPlainDigestSigner implements Signer {

    private final Digest digest;

    private final DSA dsaSigner;

    private boolean forSigning;

    private int keyBitLen;

    DSAPlainDigestSigner(
            final DSA signer,
            final Digest digest) {
        this.digest = digest;
        this.dsaSigner = signer;
    }

    public void init(
            final boolean pForSigning,
            final CipherParameters parameters) {
        this.forSigning = pForSigning;

        AsymmetricKeyParameter k;

        if (parameters instanceof ParametersWithRandom) {
            k = (AsymmetricKeyParameter) ((ParametersWithRandom) parameters).getParameters();
        } else {
            k = (AsymmetricKeyParameter) parameters;
        }

        ParamUtil.requireNonNull("k", k);
        if (k instanceof ECPublicKeyParameters) {
            keyBitLen = ((ECPublicKeyParameters) k).getParameters().getCurve().getFieldSize();
        } else if (k instanceof ECPrivateKeyParameters) {
            keyBitLen = ((ECPrivateKeyParameters) k).getParameters().getCurve().getFieldSize();
        } else if (k instanceof DSAPublicKeyParameters) {
            keyBitLen = ((DSAPublicKeyParameters) k).getParameters().getQ().bitLength();
        } else if (k instanceof DSAPrivateKeyParameters) {
            keyBitLen = ((DSAPrivateKeyParameters) k).getParameters().getQ().bitLength();
        } else {
            throw new IllegalArgumentException("unknown parameters: " + k.getClass().getName());
        }

        if (pForSigning && !k.isPrivate()) {
            throw new IllegalArgumentException("Signing Requires Private Key.");
        }

        if (!pForSigning && k.isPrivate()) {
            throw new IllegalArgumentException("Verification Requires Public Key.");
        }

        reset();

        dsaSigner.init(pForSigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
            final byte input) {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
            final byte[] input,
            final int inOff,
            final int length) {
        digest.update(input, inOff, length);
    }

    /**
     * Generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generateSignature() {
        if (!forSigning) {
            throw new IllegalStateException(
                    "DSADigestSigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        BigInteger[] sig = dsaSigner.generateSignature(hash);

        try {
            return encode(sig[0], sig[1]);
        } catch (IOException ex) {
            throw new IllegalStateException("unable to encode signature");
        }
    }

    public boolean verifySignature(
            final byte[] signature) {
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

    public void reset() {
        digest.reset();
    }

    private byte[] encode(
            final BigInteger r,
            final BigInteger s)
    throws IOException {
        int blockSize = (keyBitLen + 7) / 8;
        if ((r.bitLength() + 7) / 8 > blockSize) {
            throw new IOException("r is too long");
        }

        if ((s.bitLength() + 7) / 8 > blockSize) {
            throw new IOException("s is too long");
        }

        byte[] ret = new byte[2 * blockSize];

        byte[] bytes = r.toByteArray();
        int srcOffset = Math.max(0, bytes.length - blockSize);
        System.arraycopy(bytes, srcOffset, ret, 0, bytes.length - srcOffset);

        bytes = s.toByteArray();
        srcOffset = Math.max(0, bytes.length - blockSize);
        System.arraycopy(bytes, srcOffset, ret, blockSize, bytes.length - srcOffset);
        return ret;
    }

    private BigInteger[] decode(
            final byte[] encoding)
    throws IOException {
        int blockSize = (keyBitLen + 7) / 8;
        if (encoding.length != 2 * blockSize) {
            throw new IOException("invalid length of signature");
        }

        BigInteger[] ret = new BigInteger[2];
        byte[] buffer = new byte[blockSize];
        System.arraycopy(encoding, 0, buffer, 0, blockSize);
        ret[0] = new BigInteger(1, buffer);

        System.arraycopy(encoding, blockSize, buffer, 0, blockSize);
        ret[1] = new BigInteger(1, buffer);
        return ret;
    }

}
