/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.security.pkcs12;

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
import org.xipki.commons.security.exception.XiSecurityException;
import org.xipki.commons.security.util.SignerUtil;

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
