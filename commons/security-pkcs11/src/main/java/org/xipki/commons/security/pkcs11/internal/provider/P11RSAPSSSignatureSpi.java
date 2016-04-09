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

package org.xipki.commons.security.pkcs11.internal.provider;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.commons.security.pkcs11.internal.P11PlainRSASigner;
import org.xipki.commons.security.pkcs11.internal.P11RSAKeyParameter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11RSAPSSSignatureSpi extends SignatureSpi {

    // CHECKSTYLE:SKIP
    public static class NonePSS extends P11RSAPSSSignatureSpi {

        public NonePSS() {
            super(null, true);
        }

    } // class nonePSS

    // CHECKSTYLE:SKIP
    public static class PSSwithRSA extends P11RSAPSSSignatureSpi {

        public PSSwithRSA() {
            super(null);
        }

    } // class PSSwithRSA

    // CHECKSTYLE:SKIP
    public static class SHA1withRSA extends P11RSAPSSSignatureSpi {

        public SHA1withRSA() {
            super(PSSParameterSpec.DEFAULT);
        }

    } // class SHA1withRSA

    // CHECKSTYLE:SKIP
    public static class SHA224withRSA extends P11RSAPSSSignatureSpi {

        public SHA224withRSA() {
            super(new PSSParameterSpec("SHA-224", "MGF1",
                    new MGF1ParameterSpec("SHA-224"), 28, 1));
        }

    } // class SHA224withRSA

    // CHECKSTYLE:SKIP
    public static class SHA256withRSA extends P11RSAPSSSignatureSpi {

        public SHA256withRSA() {
            super(new PSSParameterSpec("SHA-256", "MGF1",
                    new MGF1ParameterSpec("SHA-256"), 32, 1));
        }

    } // class SHA256withRSA

    // CHECKSTYLE:SKIP
    public static class SHA384withRSA extends P11RSAPSSSignatureSpi {

        public SHA384withRSA() {
            super(new PSSParameterSpec("SHA-384", "MGF1",
                    new MGF1ParameterSpec("SHA-384"), 48, 1));
        }

    } // class SHA384withRSA

    // CHECKSTYLE:SKIP
    public static class SHA512withRSA extends P11RSAPSSSignatureSpi {

        public SHA512withRSA() {
            super(new PSSParameterSpec("SHA-512", "MGF1",
                    new MGF1ParameterSpec("SHA-512"), 64, 1));
        }

    } // class SHA512withRSA

    private static class NullPssDigest implements Digest {

        private ByteArrayOutputStream baOut = new ByteArrayOutputStream();

        private Digest baseDigest;

        private boolean oddTime = true;

        NullPssDigest(
                final Digest mgfDigest) {
            this.baseDigest = mgfDigest;
        }

        public String getAlgorithmName() {
            return "NULL";
        }

        public int getDigestSize() {
            return baseDigest.getDigestSize();
        }

        public void update(
                final byte in) {
            baOut.write(in);
        }

        public void update(
                final byte[] in,
                final int inOff,
                final int len) {
            baOut.write(in, inOff, len);
        }

        public int doFinal(
                final byte[] out,
                final int outOff) {
            byte[] res = baOut.toByteArray();

            if (oddTime) {
                System.arraycopy(res, 0, out, outOff, res.length);
            } else {
                baseDigest.update(res, 0, res.length);

                baseDigest.doFinal(out, outOff);
            }

            reset();

            oddTime = !oddTime;

            return res.length;
        }

        public void reset() {
            baOut.reset();
            baseDigest.reset();
        }

    } // class NullPssDigest

    private AlgorithmParameters engineParams;

    private PSSParameterSpec paramSpec;

    private PSSParameterSpec originalSpec;

    private P11PlainRSASigner signer = new P11PlainRSASigner();

    private Digest contentDigest;

    private Digest mgfDigest;

    private int saltLength;

    private byte trailer;

    private boolean isRaw;

    private P11PrivateKey signingKey;

    private org.bouncycastle.crypto.signers.PSSSigner pss;

    protected P11RSAPSSSignatureSpi(
            final PSSParameterSpec paramSpecArg) {
        this(paramSpecArg, false);
    }

    protected P11RSAPSSSignatureSpi(
            final PSSParameterSpec baseParamSpec,
            final boolean isRaw) {
        this.originalSpec = baseParamSpec;

        if (baseParamSpec == null) {
            this.paramSpec = PSSParameterSpec.DEFAULT;
        } else {
            this.paramSpec = baseParamSpec;
        }

        this.mgfDigest = DigestFactory.getDigest(paramSpec.getDigestAlgorithm());
        this.saltLength = paramSpec.getSaltLength();
        this.trailer = getTrailer(paramSpec.getTrailerField());
        this.isRaw = isRaw;

        setupContentDigest();
    }

    protected void engineInitVerify(
            final PublicKey publicKey)
    throws InvalidKeyException {
        throw new UnsupportedOperationException("engineInitVerify unsupported");
    }

    protected void engineInitSign(
            final PrivateKey privateKey,
            final SecureRandom random)
    throws InvalidKeyException {
        if (!(privateKey instanceof P11PrivateKey)) {
            throw new InvalidKeyException("privateKey is not instanceof "
                    + P11PrivateKey.class.getName());
        }

        String algo = privateKey.getAlgorithm();
        if (!"RSA".equals(algo)) {
            throw new InvalidKeyException("privateKey is not an RSA private key: " + algo);
        }

        this.signingKey = (P11PrivateKey) privateKey;

        pss = new org.bouncycastle.crypto.signers.PSSSigner(
                signer, contentDigest, mgfDigest, saltLength, trailer);

        P11RSAKeyParameter p11KeyParam = P11RSAKeyParameter.getInstance(
                signingKey.getP11CryptService(), signingKey.getIdentityId());
        if (random == null) {
            pss.init(true, p11KeyParam);
        } else {
            pss.init(true, new ParametersWithRandom(p11KeyParam, random));
        }
    }

    @Override
    protected void engineInitSign(
            final PrivateKey privateKey)
    throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineUpdate(
            final byte input)
    throws SignatureException {
        pss.update(input);
    }

    @Override
    protected void engineUpdate(
            final byte[] input,
            final int off,
            final int len)
    throws SignatureException {
        pss.update(input, off, len);
    }

    @Override
    protected byte[] engineSign()
    throws SignatureException {
        try {
            return pss.generateSignature();
        } catch (CryptoException ex) {
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
            final AlgorithmParameterSpec params)
    throws InvalidParameterException {
        if (params instanceof PSSParameterSpec) {
            PSSParameterSpec newParamSpec = (PSSParameterSpec) params;

            if (originalSpec != null) {
                if (!DigestFactory.isSameDigest(originalSpec.getDigestAlgorithm(),
                        newParamSpec.getDigestAlgorithm())) {
                    throw new InvalidParameterException("parameter must be using "
                            + originalSpec.getDigestAlgorithm());
                }
            }
            if (!newParamSpec.getMGFAlgorithm().equalsIgnoreCase("MGF1")
                    && !newParamSpec.getMGFAlgorithm().equals(
                            PKCSObjectIdentifiers.id_mgf1.getId())) {
                throw new InvalidParameterException("unknown mask generation function specified");
            }

            if (!(newParamSpec.getMGFParameters() instanceof MGF1ParameterSpec)) {
                throw new InvalidParameterException("unkown MGF parameters");
            }

            MGF1ParameterSpec mgfParams = (MGF1ParameterSpec) newParamSpec.getMGFParameters();

            if (!DigestFactory.isSameDigest(mgfParams.getDigestAlgorithm(),
                    newParamSpec.getDigestAlgorithm())) {
                throw new InvalidParameterException(
                        "digest algorithm for MGF should be the same as for PSS parameters.");
            }

            Digest newDigest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());

            if (newDigest == null) {
                throw new InvalidParameterException(
                        "no match on MGF digest algorithm: " + mgfParams.getDigestAlgorithm());
            }

            this.engineParams = null;
            this.paramSpec = newParamSpec;
            this.mgfDigest = newDigest;
            this.saltLength = paramSpec.getSaltLength();
            this.trailer = getTrailer(paramSpec.getTrailerField());

            setupContentDigest();
        } else {
            throw new InvalidParameterException("only PSSParameterSpec supported");
        }
    } // method engineSetParameter

    @Override
    protected void engineSetParameter(
            final String param,
            final Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (engineParams == null) {
            if (paramSpec != null) {
                try {
                    engineParams = AlgorithmParameters.getInstance("PSS",
                            BouncyCastleProvider.PROVIDER_NAME);
                    engineParams.init(paramSpec);
                } catch (Exception ex) {
                    throw new RuntimeException(ex.getMessage(), ex);
                }
            }
        }

        return engineParams;
    }

    @Override
    protected Object engineGetParameter(
            final String param) {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    private byte getTrailer(
            final int trailerField) {
        if (trailerField == 1) {
            return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
        }

        throw new IllegalArgumentException("unknown trailer field");
    }

    private void setupContentDigest() {
        if (isRaw) {
            this.contentDigest = new NullPssDigest(mgfDigest);
        } else {
            this.contentDigest = mgfDigest;
        }
    }

}
