/*
 * Copyright 2014 xipki.org
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;
import org.xipki.security.bcext.BcRSAContentVerifierProviderBuilder;
import org.xipki.security.bcext.ECDSAContentVerifierProviderBuilder;

public class KeyUtil
{
    private static final DefaultDigestAlgorithmIdentifierFinder dfltDigesAlgIdentifierFinder =
            new DefaultDigestAlgorithmIdentifierFinder();

    private static final Map<String, BcContentVerifierProviderBuilder> verifierProviderBuilders =
            new HashMap<String, BcContentVerifierProviderBuilder>();

    private static final Map<String, KeyFactory> keyFactories = new HashMap<String, KeyFactory>();

    public static ContentVerifierProvider getContentVerifierProvider(
            X509Certificate verifierCert)
    throws InvalidKeyException, OperatorCreationException
    {
        PublicKey publicKey = verifierCert.getPublicKey();
        String keyAlg = publicKey.getAlgorithm().toUpperCase();
        if(keyAlg.equals("EC"))
        {
            keyAlg = "ECDSA";
        }

        BcContentVerifierProviderBuilder builder = verifierProviderBuilders.get(keyAlg);
        if(builder == null)
        {
            if("RSA".equals(keyAlg))
            {
                builder = new BcRSAContentVerifierProviderBuilder(dfltDigesAlgIdentifierFinder);
            }
            else if("DSA".equals(keyAlg))
            {
                builder = new BcDSAContentVerifierProviderBuilder(dfltDigesAlgIdentifierFinder);
            }
            else if("ECDSA".equals(keyAlg))
            {
                builder = new ECDSAContentVerifierProviderBuilder(dfltDigesAlgIdentifierFinder);
            }
            else
            {
                throw new InvalidKeyException("unknown key algorithm of the public key " + keyAlg);
            }
            verifierProviderBuilders.put(keyAlg, builder);
        }

        AsymmetricKeyParameter keyParam = KeyUtil.generatePublicKeyParameter(publicKey);
        return builder.build(keyParam);
    }

    public static ContentVerifierProvider getContentVerifierProvider(
            PublicKey publicKey)
    throws OperatorCreationException, InvalidKeyException
    {
        String keyAlg = publicKey.getAlgorithm().toUpperCase();
        if(keyAlg.equals("EC"))
        {
            keyAlg = "ECDSA";
        }

        BcContentVerifierProviderBuilder builder = verifierProviderBuilders.get(keyAlg);
        if(builder == null)
        {
            if("RSA".equals(keyAlg))
            {
                builder = new BcRSAContentVerifierProviderBuilder(dfltDigesAlgIdentifierFinder);
            }
            else if("DSA".equals(keyAlg))
            {
                builder = new BcDSAContentVerifierProviderBuilder(dfltDigesAlgIdentifierFinder);
            }
            else if("ECDSA".equals(keyAlg))
            {
                builder = new ECDSAContentVerifierProviderBuilder(dfltDigesAlgIdentifierFinder);
            }
            else
            {
                throw new OperatorCreationException("unknown key algorithm of the public key " + keyAlg);
            }
            verifierProviderBuilders.put(keyAlg, builder);
        }

        AsymmetricKeyParameter keyParam = KeyUtil.generatePublicKeyParameter(publicKey);
        return builder.build(keyParam);
    }

    public static KeyPair generateRSAKeypair(int keySize)
    throws Exception
    {
        return generateRSAKeypair(keySize, null);
    }

    public static KeyPair generateRSAKeypair(int keySize, BigInteger publicExponent)
    throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        if(publicExponent == null)
        {
            publicExponent = RSAKeyGenParameterSpec.F4;
        }
        AlgorithmParameterSpec params = new RSAKeyGenParameterSpec(keySize,    publicExponent);
        kpGen.initialize(params);
        return kpGen.generateKeyPair();
    }

    public static KeyPair generateECKeypair(ASN1ObjectIdentifier curveId, char[] password)
    throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveId.getId());
        kpGen.initialize(spec);
        return kpGen.generateKeyPair();
    }

    private static KeyFactory getKeyFactory(String algorithm)
    throws InvalidKeySpecException
    {
        synchronized (keyFactories)
        {
            KeyFactory kf = keyFactories.get(algorithm);
            if(kf == null)
            {
                try
                {
                    kf = KeyFactory.getInstance(algorithm, "BC");
                } catch (NoSuchAlgorithmException e)
                {
                    throw new InvalidKeySpecException("Could not find KeyFactory for " + algorithm + ": " + e.getMessage());
                } catch (NoSuchProviderException e)
                {
                    throw new InvalidKeySpecException("Could not find KeyFactory for " + algorithm + ": " + e.getMessage());
                }
                keyFactories.put(algorithm, kf);
            }

            return kf;
        }
    }

    public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
    throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        KeyFactory kf;
        if(PKCSObjectIdentifiers.rsaEncryption.equals(aid))
        {
            kf = KeyFactory.getInstance("RSA");
        }
        else if(X9ObjectIdentifiers.id_ecPublicKey.equals(aid))
        {
            kf = KeyFactory.getInstance("ECDSA");
        }
        else
        {
            throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
        }

        return kf.generatePublic(keyspec);
    }

    public static RSAPublicKey generateRSAPublicKey(BigInteger modulus, BigInteger publicExponent)
    throws InvalidKeySpecException
    {
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory kf = getKeyFactory("RSA");
        synchronized (kf)
        {
            return (RSAPublicKey) kf.generatePublic(keySpec);
        }
    }

    public static ECPublicKey generateECPublicKey(String curveOid, byte[] encodedQ)
    throws InvalidKeySpecException
    {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveOid);
        ECPoint q = spec.getCurve().decodePoint(encodedQ);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(q, spec);

        KeyFactory kf = getKeyFactory("EC");
        synchronized (kf)
        {
            return (ECPublicKey) kf.generatePublic(keySpec);
        }
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
            PrivateKey key)
    throws InvalidKeyException
    {
        if (key instanceof RSAPrivateCrtKey)
        {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

            return new RSAPrivateCrtKeyParameters(k.getModulus(),
                 k.getPublicExponent(), k.getPrivateExponent(),
                 k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());
        }
        else if(key instanceof RSAPrivateKey)
        {
            RSAPrivateKey k = (RSAPrivateKey) key;

            return new RSAKeyParameters(true, k.getModulus(), k.getPrivateExponent());
        }
        else if(key instanceof ECPrivateKey)
        {
            return ECUtil.generatePrivateKeyParameter(key);
        }
        else if(key instanceof DSAPrivateKey)
        {
               return DSAUtil.generatePrivateKeyParameter(key);
        }
        else
        {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
    throws InvalidKeyException
    {
        if (key instanceof RSAPublicKey)
        {
            RSAPublicKey k = (RSAPublicKey)key;
            return new RSAKeyParameters(false, k.getModulus(), k.getPublicExponent());
        }
        else if(key instanceof ECPublicKey)
        {
            return ECUtil.generatePublicKeyParameter(key);
        }
        else if(key instanceof DSAPublicKey)
        {
               return DSAUtil.generatePublicKeyParameter(key);
        }
        else
        {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    }

    public static byte[] generateSelfSignedRSAKeyStore(
            BigInteger serial,
            String subject,
            String keystoreType, char[] password, String keyLabel,
            int keysize, BigInteger publicExponent)
    throws SignerException
    {
        final String provider = "BC";

        try
        {
            X500Name subjectDN = new X500Name(subject);
            KeyPair keypair = KeyUtil.generateRSAKeypair(keysize, publicExponent);
            SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                    KeyUtil.generatePublicKeyParameter(keypair.getPublic()));

            KeyStore ks = KeyStore.getInstance(keystoreType, provider);
            ks.load(null, password);

            Date dummyNotBefore = new Date();
            Date dummyNotAfter = new Date(dummyNotBefore.getTime() + 3650L*24*3600*1000);
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    subjectDN, serial, dummyNotBefore, dummyNotAfter, subjectDN,
                    pkInfo);
            X509KeyUsage ku = new X509KeyUsage(
                    X509KeyUsage.nonRepudiation + X509KeyUsage.digitalSignature +
                    X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
            certBuilder.addExtension(
                    X509Extension.keyUsage, true, ku);

            SoftTokenContentSignerBuilder signerBuilder = new SoftTokenContentSignerBuilder(
                    keypair.getPrivate());

            ConcurrentContentSigner concurrentSigner = signerBuilder.createSigner(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE), 1);

            ContentSigner signer = concurrentSigner.borrowContentSigner();
            X509CertificateObject cert;
            try
            {
                cert = new X509CertificateObject(
                    certBuilder.build(signer).toASN1Structure());
            }finally
            {
                concurrentSigner.returnContentSigner(signer);
            }

            if(keyLabel == null)
            {
                keyLabel = "main";
            }

            ks.setKeyEntry(keyLabel, keypair.getPrivate(), password, new Certificate[]{cert});
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, password);
            out.flush();

            return out.toByteArray();
        }catch(SignerException e)
        {
            throw e;
        }catch(Exception e)
        {
            throw new SignerException(e);
        }
    }

}
