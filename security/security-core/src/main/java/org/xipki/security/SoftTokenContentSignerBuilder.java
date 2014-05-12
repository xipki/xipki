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
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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

public class SoftTokenContentSignerBuilder
{
    private static final Logger LOG = LoggerFactory.getLogger(SoftTokenContentSignerBuilder.class);

    private final PrivateKey key;
    private final X509Certificate cert;

    public SoftTokenContentSignerBuilder(PrivateKey privateKey)
    throws SignerException
    {
        this.key = privateKey;
        this.cert = null;
    }

    public SoftTokenContentSignerBuilder(String keystoreType, InputStream keystoreStream,
            char[] keystorePassword, String keyname, char[] keyPassword, X509Certificate cert)
    throws SignerException
    {
        if(("PKCS12".equalsIgnoreCase(keystoreType) || "JKS".equalsIgnoreCase(keystoreType)) == false)
        {
            throw new IllegalArgumentException("Unsupported keystore type: " + keystoreType);
        }

        if(keystoreStream == null)
            throw new IllegalArgumentException("keystoreStream is null");
        if(keystorePassword == null)
            throw new IllegalArgumentException("keystorePassword is null");
        if(keyPassword == null)
            throw new IllegalArgumentException("keyPassword is null");

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

            if(cert == null)
            {
                cert = (X509Certificate) ks.getCertificate(keyname);
            }
            this.cert = cert;
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

        if(key instanceof ECPrivateKey)
        {
            final String provider = "SunEC";
            ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();
            String algoName;

            if(X9ObjectIdentifiers.ecdsa_with_SHA1.equals(algOid))
            {
                algoName = "SHA1withECDSA";
            }
            else if(X9ObjectIdentifiers.ecdsa_with_SHA224.equals(algOid))
            {
                algoName = "SHA224withECDSA";
            }
            else if(X9ObjectIdentifiers.ecdsa_with_SHA256.equals(algOid))
            {
                algoName = "SHA256withECDSA";
            }
            else if(X9ObjectIdentifiers.ecdsa_with_SHA384.equals(algOid))
            {
                algoName = "SHA384withECDSA";
            }
            else if(X9ObjectIdentifiers.ecdsa_with_SHA512.equals(algOid))
            {
                algoName = "SHA512withECDSA";
            }
            else
            {
                throw new OperatorCreationException("Unsupported ECDSA signature algorithm " + algOid.getId());
            }

            for(int i = 0; i < parallelism; i++)
            {
                try
                {
                    Signature signature = Signature.getInstance(algoName, provider);
                    signature.initSign(key);
                    signature.update(new byte[]{1,2,3,4});
                    signature.sign();
                    ContentSigner signer = new SignatureSigner(signatureAlgId, signature, key);
                    signers.add(signer);
                } catch (Exception e)
                {
                    LOG.warn("Could not use {} for {}", provider, algoName);
                    signers.clear();
                    break;
                }
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
        concurrentSigner.setCertificate(cert);
        return concurrentSigner;
    }

    public X509Certificate getCert()
    {
        return cert;
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
                return SignerUtil.createPSSRSASigner(sigAlgId);
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
}
