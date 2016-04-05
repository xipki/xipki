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

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.p11.P11Constants;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
class P11RSADigestSignatureSpi extends SignatureSpi {

    // CHECKSTYLE:SKIP
    class SHA1 extends P11RSADigestSignatureSpi {

        SHA1() {
            super(HashAlgoType.SHA1);
        }

    } // class SHA1

    // CHECKSTYLE:SKIP
    class SHA224 extends P11RSADigestSignatureSpi {

        SHA224() {
            super(HashAlgoType.SHA224);
        }

    } // class SHA224

    // CHECKSTYLE:SKIP
    class SHA256 extends P11RSADigestSignatureSpi {

        SHA256() {
            super(HashAlgoType.SHA256);
        }

    } // class SHA256

    // CHECKSTYLE:SKIP
    class SHA384 extends P11RSADigestSignatureSpi {

        SHA384() {
            super(HashAlgoType.SHA384);
        }

    } // class SHA384

    // CHECKSTYLE:SKIP
    class SHA512 extends P11RSADigestSignatureSpi {

        SHA512() {
            super(HashAlgoType.SHA512);
        }

    } // class SHA512

    // CHECKSTYLE:SKIP
    class NoneRSA extends P11RSADigestSignatureSpi {

        NoneRSA() {
            super(new NullDigest());
        }

    } // class NoneRSA

    private Digest digest;

    private AlgorithmIdentifier digestAlgId;

    private P11PrivateKey signingKey;

    protected P11RSADigestSignatureSpi(
            final Digest digest) {
        this.digest = digest;
        this.digestAlgId = null;
    }

    protected P11RSADigestSignatureSpi(
            final HashAlgoType digestAlg) {
        this.digestAlgId = digestAlg.getAlgorithmIdentifier();
        this.digest = digestAlg.createDigest();
    }

    @Override
    protected void engineInitVerify(
            final PublicKey publicKey)
    throws InvalidKeyException {
        throw new UnsupportedOperationException("engineVerify unsupported");
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
        if (!"RSA".equals(algo)) {
            throw new InvalidKeyException("privateKey is not an RSA private key: " + algo);
        }

        digest.reset();
        this.signingKey = (P11PrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(
            final byte input)
    throws SignatureException {
        digest.update(input);
    }

    @Override
    protected void engineUpdate(
            final byte[] input,
            final int off,
            final int len)
    throws SignatureException {
        digest.update(input, off, len);
    }

    @Override
    protected byte[] engineSign()
    throws SignatureException {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try {
            byte[] bytes = derEncode(hash);
            return signingKey.sign(P11Constants.CKM_RSA_PKCS, null, bytes);
        } catch (ArrayIndexOutOfBoundsException ex) {
            throw new SignatureException("key too small for signature type");
        } catch (Exception ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    @Override
    protected boolean engineVerify(
            final byte[] sigBytes)
    throws SignatureException {
        throw new UnsupportedOperationException("engineVerify unsupported");
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
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private byte[] derEncode(
            final byte[] hash)
    throws IOException {
        if (digestAlgId == null) {
            // For raw RSA, the DigestInfo must be prepared externally
            return hash;
        }

        DigestInfo digestInfo = new DigestInfo(digestAlgId, hash);
        return digestInfo.getEncoded(ASN1Encoding.DER);
    }

}
