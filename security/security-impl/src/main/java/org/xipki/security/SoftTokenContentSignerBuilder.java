/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.util.AlgorithmUtil;
import org.xipki.security.api.util.X509Util;
import org.xipki.security.bcext.BCRSAPrivateCrtKey;
import org.xipki.security.bcext.BCRSAPrivateKey;
import org.xipki.security.bcext.DSAPlainDigestSigner;

/**
 * @author Lijun Liao
 */

public class SoftTokenContentSignerBuilder
{
    private static final Logger LOG = LoggerFactory.getLogger(SoftTokenContentSignerBuilder.class);
    public static final String PROVIDER_XIPKI_NSS = "XipkiNSS";
    public static final String PROVIDER_XIPKI_NSS_CIPHER = "SunPKCS11-XipkiNSS";

    private final PrivateKey key;
    private final X509Certificate[] certificateChain;

    public SoftTokenContentSignerBuilder(
            final PrivateKey privateKey)
    throws SignerException
    {
        this.key = privateKey;
        this.certificateChain = null;
    }

    public SoftTokenContentSignerBuilder(
            final String keystoreType,
            final InputStream keystoreStream,
            final char[] keystorePassword,
            String keyname,
            final char[] keyPassword,
            final X509Certificate[] certificateChain)
    throws SignerException
    {
        if(("PKCS12".equalsIgnoreCase(keystoreType) || "JKS".equalsIgnoreCase(keystoreType)) == false)
        {
            throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
        }

        ParamUtil.assertNotNull("keystoreStream", keystoreStream);
        ParamUtil.assertNotNull("keystorePassword", keystorePassword);
        ParamUtil.assertNotNull("keyPassword", keyPassword);

        try
        {
            KeyStore ks;
            if("JKS".equalsIgnoreCase(keystoreType))
            {
                ks = KeyStore.getInstance(keystoreType);
            }
            else
            {
                ks = KeyStore.getInstance(keystoreType, "BC");
            }
            ks.load(keystoreStream, keystorePassword);

            if(keyname == null)
            {
                Enumeration<String> aliases = ks.aliases();
                while(aliases.hasMoreElements())
                {
                    String alias = aliases.nextElement();
                    if(ks.isKeyEntry(alias))
                    {
                        keyname = alias;
                        break;
                    }
                }
            }
            else
            {
                if(ks.isKeyEntry(keyname) == false)
                {
                    throw new SignerException("unknown key named " + keyname);
                }
            }

            this.key = (PrivateKey) ks.getKey(keyname, keyPassword);

            if( (key instanceof RSAPrivateKey || key instanceof DSAPrivateKey || key instanceof ECPrivateKey) == false)
            {
                throw new SignerException("unsupported key " + key.getClass().getName());
            }

            Set<Certificate> caCerts = new HashSet<>();

            X509Certificate cert;
            int n = (certificateChain == null)
                    ? 0
                    : certificateChain.length;
            if(n > 0)
            {
                cert = certificateChain[0];
                if(n > 1)
                {
                    for(int i = 1; i < n; i++)
                    {
                        caCerts.add(certificateChain[i]);
                    }
                }
            }
            else
            {
                cert = (X509Certificate) ks.getCertificate(keyname);
            }

            Certificate[] certsInKeystore = ks.getCertificateChain(keyname);
            if(certsInKeystore.length > 1)
            {
                for(int i = 1; i < certsInKeystore.length; i++)
                {
                    caCerts.add(certsInKeystore[i]);
                }
            }

            this.certificateChain = X509Util.buildCertPath(cert, caCerts);
        }catch(KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException
                | CertificateException | IOException | UnrecoverableKeyException
                | ClassCastException e)
        {
            throw new SignerException(e.getMessage(), e);
        }
    }

    public ConcurrentContentSigner createSigner(
            final AlgorithmIdentifier signatureAlgId,
            final int parallelism)
    throws OperatorCreationException, NoSuchPaddingException
    {
        if(parallelism < 1)
        {
            throw new IllegalArgumentException("non-positive parallelism is not allowed: "
                    + parallelism);
        }

        List<ContentSigner> signers = new ArrayList<>(parallelism);

        ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();

        if(Security.getProvider(PROVIDER_XIPKI_NSS) != null
                && algOid.equals(PKCSObjectIdentifiers.id_RSASSA_PSS) == false
                && key instanceof ECPrivateKey == false)
        {
            String algoName;
            try
            {
                algoName = AlgorithmUtil.getSignatureAlgoName(signatureAlgId);
            } catch (NoSuchAlgorithmException e)
            {
                throw new OperatorCreationException(e.getMessage());
            }

            boolean useGivenProvider = true;
            for(int i = 0; i < parallelism; i++)
            {
                try
                {
                    Signature signature = Signature.getInstance(algoName, PROVIDER_XIPKI_NSS);
                    signature.initSign(key);
                    if(i == 0)
                    {
                        signature.update(new byte[]{1,2,3,4});
                        signature.sign();
                    }
                    ContentSigner signer = new SignatureSigner(signatureAlgId, signature, key);
                    signers.add(signer);
                } catch (Exception e)
                {
                    useGivenProvider = false;
                    signers.clear();
                    break;
                }
            }

            if(useGivenProvider)
            {
                LOG.info("use {} to sign {} signature", PROVIDER_XIPKI_NSS, algoName);
            }
            else
            {
                LOG.info("could not use {} to sign {} signature", PROVIDER_XIPKI_NSS, algoName);
            }
        }

        if(CollectionUtil.isEmpty(signers))
        {
            BcContentSignerBuilder signerBuilder;
            AsymmetricKeyParameter keyparam;
            try
            {
                if(key instanceof RSAPrivateKey)
                {
                    keyparam = SignerUtil.generateRSAPrivateKeyParameter((RSAPrivateKey) key);
                    signerBuilder = new RSAContentSignerBuilder(signatureAlgId);
                }
                else if(key instanceof DSAPrivateKey)
                {
                    keyparam = DSAUtil.generatePrivateKeyParameter(key);
                    signerBuilder = new DSAContentSignerBuilder(signatureAlgId,
                            AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
                }
                else if(key instanceof ECPrivateKey)
                {
                    keyparam = ECUtil.generatePrivateKeyParameter(key);
                    signerBuilder = new ECDSAContentSignerBuilder(signatureAlgId,
                            AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
                }
                else
                {
                    throw new OperatorCreationException("unsupported key " + key.getClass().getName());
                }
            } catch (InvalidKeyException e)
            {
                throw new OperatorCreationException("invalid key", e);
            } catch (NoSuchAlgorithmException e)
            {
                throw new OperatorCreationException("no such algorithm", e);
            }

            for(int i = 0; i < parallelism; i++)
            {
                ContentSigner signer = signerBuilder.build(keyparam);
                signers.add(signer);
            }
        }

        ConcurrentContentSigner concurrentSigner = new DefaultConcurrentContentSigner(signers, key);
        if(certificateChain != null)
        {
            concurrentSigner.setCertificateChain(certificateChain);
        }
        return concurrentSigner;
    }

    public X509Certificate getCert()
    {
        if(certificateChain != null && certificateChain.length > 0)
        {
            return certificateChain[0];
        }
        else
        {
            return null;
        }
    }

    public X509Certificate[] getCertificateChain()
    {
        return certificateChain;
    }

    public PrivateKey getKey()
    {
        return key;
    }

    private static class RSAContentSignerBuilder extends BcContentSignerBuilder
    {
        private RSAContentSignerBuilder(
                final AlgorithmIdentifier signatureAlgId)
        throws NoSuchAlgorithmException, NoSuchPaddingException
        {
            super(signatureAlgId, AlgorithmUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
        }

        protected Signer createSigner(
                final AlgorithmIdentifier sigAlgId,
                final AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
        {
            if(AlgorithmUtil.isRSASignatureAlgoId(sigAlgId) == false)
            {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid RSA signature algirthm '"
                        + sigAlgId.getAlgorithm().getId() + "'");
            }

            if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm()))
            {
                if(Security.getProvider(PROVIDER_XIPKI_NSS_CIPHER) != null)
                {
                    NssPlainRSASigner plainRSASigner;
                    try
                    {
                        plainRSASigner = new NssPlainRSASigner();
                    } catch (NoSuchAlgorithmException e)
                    {
                        throw new OperatorCreationException(e.getMessage(), e);
                    } catch (NoSuchProviderException e)
                    {
                        throw new OperatorCreationException(e.getMessage(), e);
                    } catch (NoSuchPaddingException e)
                    {
                        throw new OperatorCreationException(e.getMessage(), e);
                    }
                    return SignerUtil.createPSSRSASigner(sigAlgId, plainRSASigner);
                }
                else
                {
                    return SignerUtil.createPSSRSASigner(sigAlgId);
                }
            } else
            {
                Digest dig = digestProvider.get(digAlgId);
                return new RSADigestSigner(dig);
            }
        }

    } // RSAContentSignerBuilder

    private static class DSAContentSignerBuilder extends BcContentSignerBuilder
    {
        private final boolean plain;

        private DSAContentSignerBuilder(
                final AlgorithmIdentifier signatureAlgId,
                final boolean plain)
        throws NoSuchAlgorithmException
        {
            super(signatureAlgId, AlgorithmUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
            this.plain = plain;
        }

        protected Signer createSigner(
                final AlgorithmIdentifier sigAlgId,
                final AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
        {
            if(AlgorithmUtil.isDSASigAlg(sigAlgId) == false)
            {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid DSA signature algirthm '"
                        + sigAlgId.getAlgorithm().getId() + "'");
            }

            Digest dig = digestProvider.get(digAlgId);
            DSASigner dsaSigner = new DSASigner();
            if(plain)
            {
                return new DSAPlainDigestSigner(dsaSigner, dig);
            }
            else
            {
                return new DSADigestSigner(dsaSigner, dig);
            }
        }
    } // DSAContentSignerBuilder

    private static class ECDSAContentSignerBuilder extends BcContentSignerBuilder
    {
        private final boolean plain;

        private ECDSAContentSignerBuilder(
                final AlgorithmIdentifier signatureAlgId,
                final boolean plain)
        throws NoSuchAlgorithmException
        {
            super(signatureAlgId, AlgorithmUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
            this.plain = plain;
        }

        protected Signer createSigner(
                final AlgorithmIdentifier sigAlgId,
                final AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
        {
            if(AlgorithmUtil.isECSigAlg(sigAlgId) == false)
            {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid EC signature algirthm '"
                        + sigAlgId.getAlgorithm().getId() + "'");
            }

            Digest dig = digestProvider.get(digAlgId);
            ECDSASigner dsaSigner = new ECDSASigner();

            if(plain)
            {
                return new DSAPlainDigestSigner(dsaSigner, dig);
            }
            else
            {
                return new DSADigestSigner(dsaSigner, dig);
            }
        }
    } // ECDSAContentSignerBuilder

    public static class NssPlainRSASigner implements AsymmetricBlockCipher
    {
        private static final String algorithm = "RSA/ECB/NoPadding";
        private Cipher cipher;
        private RSAKeyParameters key;

        public NssPlainRSASigner()
        throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
        {
            cipher = Cipher.getInstance(algorithm, "SunPKCS11-XipkiNSS");
        }

        @Override
        public void init(
                final boolean forEncryption,
                final CipherParameters param)
        {
            if(forEncryption == false)
            {
                throw new RuntimeCryptoException("verification mode not supported.");
            }

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom    rParam = (ParametersWithRandom)param;

                key = (RSAKeyParameters)rParam.getParameters();
            }
            else
            {
                key = (RSAKeyParameters)param;
            }

            RSAPrivateKey signingKey;
            if(key instanceof RSAPrivateCrtKeyParameters)
            {
                signingKey = new BCRSAPrivateCrtKey((RSAPrivateCrtKeyParameters) key);
            }
            else
            {
                signingKey = new BCRSAPrivateKey(key);
            }

            try
            {
                cipher.init(Cipher.ENCRYPT_MODE, signingKey);
            } catch (InvalidKeyException e)
            {
                e.printStackTrace();
                throw new RuntimeCryptoException("could not initialize the cipher: " + e.getMessage());
            }
        }

        @Override
        public int getInputBlockSize()
        {
            return (key.getModulus().bitLength() + 7) / 8;
        }

        @Override
        public int getOutputBlockSize()
        {
            return (key.getModulus().bitLength() + 7) / 8;
        }

        @Override
        public byte[] processBlock(
                final byte[] in,
                final int inOff,
                final int len)
        throws InvalidCipherTextException
        {
            try
            {
                return cipher.doFinal(in, 0, in.length);
            } catch (IllegalBlockSizeException | BadPaddingException e)
            {
                throw new InvalidCipherTextException(e.getMessage(), e);
            }
        }
    }

}
