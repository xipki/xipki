/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.provider;

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
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.security.p11.P11PlainRSASigner;
import org.xipki.security.p11.P11RSAKeyParameter;

/**
 * @author Lijun Liao
 */

class RSAPSSSignatureSpi
    extends SignatureSpi
{
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

    private byte getTrailer(
        int trailerField)
    {
        if (trailerField == 1)
        {
            return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
        }

        throw new IllegalArgumentException("unknown trailer field");
    }

    private void setupContentDigest()
    {
        if (isRaw)
        {
            this.contentDigest = new NullPssDigest(mgfDigest);
        }
        else
        {
            this.contentDigest = mgfDigest;
        }
    }

    protected RSAPSSSignatureSpi(
        PSSParameterSpec paramSpecArg)
    {
        this(paramSpecArg, false);
    }

    protected RSAPSSSignatureSpi(
        PSSParameterSpec baseParamSpec,
        boolean isRaw)
    {
        this.originalSpec = baseParamSpec;

        if (baseParamSpec == null)
        {
            this.paramSpec = PSSParameterSpec.DEFAULT;
        }
        else
        {
            this.paramSpec = baseParamSpec;
        }

        this.mgfDigest = DigestFactory.getDigest(paramSpec.getDigestAlgorithm());
        this.saltLength = paramSpec.getSaltLength();
        this.trailer = getTrailer(paramSpec.getTrailerField());
        this.isRaw = isRaw;

        setupContentDigest();
    }

    protected void engineInitVerify(
        PublicKey publicKey)
    throws InvalidKeyException
    {
        throw new UnsupportedOperationException("engineInitVerify unsupported");
    }

    protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
    throws InvalidKeyException
    {
        if(privateKey instanceof P11PrivateKey == false)
        {
            throw new InvalidKeyException("privateKey is not instanceof " + P11PrivateKey.class.getName());
        }

        String algo = privateKey.getAlgorithm();
        if("RSA".equals(algo) == false)
        {
            throw new InvalidKeyException("privateKey is not an RSA private key: " + algo);
        }

        this.signingKey = (P11PrivateKey) privateKey;

        pss = new org.bouncycastle.crypto.signers.PSSSigner(
                signer, contentDigest, mgfDigest, saltLength, trailer);

        P11RSAKeyParameter p11RSAKeyParam = P11RSAKeyParameter.getInstance(signingKey.getP11CryptService(),
                signingKey.getSlotId(), signingKey.getKeyId());
        pss.init(true, p11RSAKeyParam);
    }

    protected void engineInitSign(
        PrivateKey privateKey)
    throws InvalidKeyException
    {
        engineInitSign(privateKey, null);
    }

    protected void engineUpdate(
        byte    b)
    throws SignatureException
    {
        pss.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len)
    throws SignatureException
    {
        pss.update(b, off, len);
    }

    protected byte[] engineSign()
    throws SignatureException
    {
        try
        {
            return pss.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes)
    throws SignatureException
    {
        throw new UnsupportedOperationException("engineVerify unsupported");
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    throws InvalidParameterException
    {
        if (params instanceof PSSParameterSpec)
        {
            PSSParameterSpec newParamSpec = (PSSParameterSpec)params;

            if (originalSpec != null)
            {
                if (DigestFactory.isSameDigest(originalSpec.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()) == false)
                {
                    throw new InvalidParameterException("parameter must be using " + originalSpec.getDigestAlgorithm());
                }
            }
            if ((newParamSpec.getMGFAlgorithm().equalsIgnoreCase("MGF1") == false) &&
                    (newParamSpec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId()) == false))
            {
                throw new InvalidParameterException("unknown mask generation function specified");
            }

            if ((newParamSpec.getMGFParameters() instanceof MGF1ParameterSpec) == false)
            {
                throw new InvalidParameterException("unkown MGF parameters");
            }

            MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)newParamSpec.getMGFParameters();

            if (DigestFactory.isSameDigest(mgfParams.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()) == false)
            {
                throw new InvalidParameterException("digest algorithm for MGF should be the same as for PSS parameters.");
            }

            Digest newDigest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());

            if (newDigest == null)
            {
                throw new InvalidParameterException("no match on MGF digest algorithm: "+ mgfParams.getDigestAlgorithm());
            }

            this.engineParams = null;
            this.paramSpec = newParamSpec;
            this.mgfDigest = newDigest;
            this.saltLength = paramSpec.getSaltLength();
            this.trailer = getTrailer(paramSpec.getTrailerField());

            setupContentDigest();
        }
        else
        {
            throw new InvalidParameterException("Only PSSParameterSpec supported");
        }
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                try
                {
                    engineParams = AlgorithmParameters.getInstance("PSS", BouncyCastleProvider.PROVIDER_NAME);
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
     */
    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

/**
 * @author Lijun Liao
 */

    static public class nonePSS
        extends RSAPSSSignatureSpi
    {
        public nonePSS()
        {
            super(null, true);
        }
    }

    static public class PSSwithRSA
        extends RSAPSSSignatureSpi
    {
        public PSSwithRSA()
        {
            super(null);
        }
    }

    static public class SHA1withRSA
        extends RSAPSSSignatureSpi
    {
        public SHA1withRSA()
        {
            super(PSSParameterSpec.DEFAULT);
        }
    }

    static public class SHA224withRSA
        extends RSAPSSSignatureSpi
    {
        public SHA224withRSA()
        {
            super(new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 28, 1));
        }
    }

    static public class SHA256withRSA
        extends RSAPSSSignatureSpi
    {
        public SHA256withRSA()
        {
            super(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        }
    }

    static public class SHA384withRSA
        extends RSAPSSSignatureSpi
    {
        public SHA384withRSA()
        {
            super(new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
        }
    }

    static public class SHA512withRSA
        extends RSAPSSSignatureSpi
    {
        public SHA512withRSA()
        {
            super(new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1));
        }
    }

    private class NullPssDigest
        implements Digest
    {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        private Digest baseDigest;
        private boolean oddTime = true;

        public NullPssDigest(Digest mgfDigest)
        {
            this.baseDigest = mgfDigest;
        }

        public String getAlgorithmName()
        {
            return "NULL";
        }

        public int getDigestSize()
        {
            return baseDigest.getDigestSize();
        }

        public void update(byte in)
        {
            bOut.write(in);
        }

        public void update(byte[] in, int inOff, int len)
        {
            bOut.write(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff)
        {
            byte[] res = bOut.toByteArray();

            if (oddTime)
            {
                System.arraycopy(res, 0, out, outOff, res.length);
            }
            else
            {
                baseDigest.update(res, 0, res.length);

                baseDigest.doFinal(out, outOff);
            }

            reset();

            oddTime = !oddTime;

            return res.length;
        }

        public void reset()
        {
            bOut.reset();
            baseDigest.reset();
        }
    }
}
