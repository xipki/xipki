/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
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
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;
import org.xipki.security.bcext.BCRSAPrivateCrtKey;
import org.xipki.security.bcext.BCRSAPrivateKey;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public class SoftTokenContentSignerBuilder
{
    private static final Logger LOG = LoggerFactory.getLogger(SoftTokenContentSignerBuilder.class);
    private static final String PROVIDER_XIPKI_NSS = "XipkiNSS";
    private static final String PROVIDER_XIPKI_NSS_CIPHER = "SunPKCS11-XipkiNSS";

    private final PrivateKey key;
    private final X509Certificate[] certificateChain;

    public SoftTokenContentSignerBuilder(PrivateKey privateKey)
    throws SignerException
    {
        this.key = privateKey;
        this.certificateChain = null;
    }

    public SoftTokenContentSignerBuilder(String keystoreType, InputStream keystoreStream,
            char[] keystorePassword, String keyname, char[] keyPassword,
            X509Certificate[] certificateChain)
    throws SignerException
    {
        if(("PKCS12".equalsIgnoreCase(keystoreType) || "JKS".equalsIgnoreCase(keystoreType)) == false)
        {
            throw new IllegalArgumentException("Unsupported keystore type: " + keystoreType);
        }

        ParamChecker.assertNotNull("keystoreStream", keystoreStream);
        ParamChecker.assertNotNull("keystorePassword", keystorePassword);
        ParamChecker.assertNotNull("keyPassword", keyPassword);

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
                throw new SignerException("Unsupported key " + key.getClass().getName());
            }

            Set<Certificate> caCerts = new HashSet<>();

            X509Certificate cert;
            int n = certificateChain == null ? 0 : certificateChain.length;
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

            this.certificateChain = IoCertUtil.buildCertPath(cert, caCerts);
        }catch(KeyStoreException e)
        {
            throw new SignerException(e);
        } catch (NoSuchProviderException e)
        {
            throw new SignerException(e);
        } catch (NoSuchAlgorithmException e)
        {
            throw new SignerException(e);
        } catch (CertificateException e)
        {
            throw new SignerException(e);
        } catch (IOException e)
        {
            throw new SignerException(e);
        } catch (UnrecoverableKeyException e)
        {
            throw new SignerException(e);
        } catch (ClassCastException e)
        {
            throw new SignerException(e);
        }
    }

    public ConcurrentContentSigner createSigner(
            AlgorithmIdentifier signatureAlgId,
            int parallelism)
    throws OperatorCreationException, NoSuchPaddingException
    {
        if(parallelism < 1)
        {
            throw new IllegalArgumentException("non-positive parallelism is not allowed: " + parallelism);
        }

        List<ContentSigner> signers = new ArrayList<ContentSigner>(parallelism);

        ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();

        if(Security.getProvider(PROVIDER_XIPKI_NSS) != null &&
                algOid.equals(PKCSObjectIdentifiers.id_RSASSA_PSS) == false)
        {
            String algoName = SignerUtil.getSignatureAlgoName(signatureAlgId);
            if(algoName == null)
            {
                throw new OperatorCreationException("Unsupported signature algorithm " + algOid.getId());
            }

            boolean useGivenProvider = true;
            for(int i = 0; i < parallelism; i++)
            {
                try
                {
                    Signature signature = Signature.getInstance(algoName, PROVIDER_XIPKI_NSS);
                    signature.initSign(key);
                    signature.update(new byte[]{1,2,3,4});
                    signature.sign();
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
                LOG.info("Use {} to sign {} signature", PROVIDER_XIPKI_NSS, algoName);
            }
            else
            {
                LOG.info("Could not use {} to sign {} signature", PROVIDER_XIPKI_NSS, algoName);
            }
        }

        if(signers.isEmpty())
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
                    signerBuilder = new DSAContentSignerBuilder(signatureAlgId);
                }
                else if(key instanceof ECPrivateKey)
                {
                     keyparam = ECUtil.generatePrivateKeyParameter(key);
                     signerBuilder = new ECDSAContentSignerBuilder(signatureAlgId);
                }
                else
                {
                    throw new OperatorCreationException("Unsupported key " + key.getClass().getName());
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
        private RSAContentSignerBuilder(AlgorithmIdentifier signatureAlgId)
        throws NoSuchAlgorithmException, NoSuchPaddingException
        {
            super(signatureAlgId, SignerUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
        }

        protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
        {
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
            }
            else
            {
                Digest dig = digestProvider.get(digAlgId);
                return new RSADigestSigner(dig);
            }
        }

    } // RSAContentSignerBuilder

    private static class DSAContentSignerBuilder extends BcContentSignerBuilder
    {
        private DSAContentSignerBuilder(AlgorithmIdentifier signatureAlgId)
        throws NoSuchAlgorithmException
        {
            super(signatureAlgId, SignerUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
        }

        protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
        {
            Digest dig = digestProvider.get(digAlgId);
               return new DSADigestSigner(new DSASigner(), dig);
        }
    } // DSAContentSignerBuilder

    private static class ECDSAContentSignerBuilder extends BcContentSignerBuilder
    {
        private ECDSAContentSignerBuilder(AlgorithmIdentifier signatureAlgId)
        throws NoSuchAlgorithmException
        {
            super(signatureAlgId, SignerUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
        }

        protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
        {
            Digest dig = digestProvider.get(digAlgId);
               return new DSADigestSigner(new ECDSASigner(), dig);
        }
    } // ECDSAContentSignerBuilder

    private static class NssPlainRSASigner implements AsymmetricBlockCipher
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
        public void init(boolean forEncryption, CipherParameters param)
        {
            if(forEncryption == false)
            {
                throw new RuntimeCryptoException("Verification mode not supported.");
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
                throw new RuntimeCryptoException("Could not initialize the cipher: " + e.getMessage());
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
        public byte[] processBlock(byte[] in, int inOff, int len)
        throws InvalidCipherTextException
        {
            try
            {
                return cipher.doFinal(in, 0, in.length);
            } catch (IllegalBlockSizeException e)
            {
                throw new InvalidCipherTextException(e.getMessage(), e);
            } catch (BadPaddingException e)
            {
                throw new InvalidCipherTextException(e.getMessage(), e);
            }
        }
    }

}
