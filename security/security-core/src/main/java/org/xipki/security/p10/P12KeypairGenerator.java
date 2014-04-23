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

package org.xipki.security.p10;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.xipki.security.KeyUtil;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.bcext.ECDSAContentSignerBuilder;

public abstract class P12KeypairGenerator
{
    private static final long MIN = 60L * 1000;
    private static final long DAY = 24L * 60 * 60 * 1000;

    private final char[] password;

    private final String subject;

    private final int serialNumber = 1;
    private final int validity = 3650;

    protected abstract KeyPairWithSubjectPublicKeyInfo genKeypair() throws Exception;
    protected abstract String getKeyAlgorithm();

    public P12KeypairGenerator(char[] password, String subject)
    throws Exception
    {
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        this.password = password;
        this.subject = subject;
    }

    public P12KeypairGenerationResult generateIentity()
    throws Exception
    {
        KeyPairWithSubjectPublicKeyInfo kp = genKeypair();

        Date now = new Date();
        Date notBefore = new Date(now.getTime() - 10 * MIN); // 10 minutes past
        Date notAfter = new Date(notBefore.getTime() + validity * DAY );

        X500Name subjectDN = new X500Name(subject);
        SubjectPublicKeyInfo subjectPublicKeyInfo = kp.getSubjectPublicKeyInfo();
        ContentSigner contentSigner = getContentSigner(kp.getKeypair().getPrivate());

        // Generate keystore
        X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
                subjectDN, BigInteger.valueOf(serialNumber), notBefore, notAfter, subjectDN, subjectPublicKeyInfo);

        X509KeyUsage ku = new X509KeyUsage(
                 X509KeyUsage.nonRepudiation + X509KeyUsage.digitalSignature +
                 X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        certGenerator.addExtension(
                 X509Extension.keyUsage, true, ku);

        KeyAndCertPair identity = new KeyAndCertPair(
             certGenerator.build(contentSigner),
             kp.getKeypair().getPrivate());

         KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
         ks.load(null, password);

         ks.setKeyEntry("main", identity.getKey(), password, new Certificate[]{identity.getJceCert()});

         ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
         try
         {
             ks.store(ksStream, password);
         }finally
         {
             ksStream.flush();
         }

        return new P12KeypairGenerationResult(
                ksStream.toByteArray(),
                identity.getCert());
    }

    private ContentSigner getContentSigner(PrivateKey key)
    throws Exception
    {
        BcContentSignerBuilder builder;

        if(key instanceof RSAPrivateKey)
        {
            ASN1ObjectIdentifier hashOid = X509ObjectIdentifiers.id_SHA1;
            ASN1ObjectIdentifier sigOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;

            builder = new BcRSAContentSignerBuilder(
                    buildAlgId(sigOid),
                    buildAlgId(hashOid));
        }

        else if(key instanceof ECPrivateKey)
        {
            ASN1ObjectIdentifier hashOid;
            ASN1ObjectIdentifier sigOid;

            int keySize = ((ECPrivateKey) key).getParams().getOrder().bitLength();
            if(keySize > 384)
            {
                hashOid = NISTObjectIdentifiers.id_sha512;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            }
            else if(keySize > 256)
            {
                hashOid = NISTObjectIdentifiers.id_sha384;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            }
            else if(keySize > 224)
            {
                hashOid = NISTObjectIdentifiers.id_sha224;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            }
            else if(keySize > 160)
            {
                hashOid = NISTObjectIdentifiers.id_sha256;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            }
            else
            {
                hashOid = X509ObjectIdentifiers.id_SHA1;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            }

            builder = new ECDSAContentSignerBuilder(
                    buildAlgId(sigOid),
                    buildAlgId(hashOid));
        }
        else
        {
            throw new IllegalArgumentException("Unknown type of key " + key.getClass().getName());
        }

        return builder.build(KeyUtil.generatePrivateKeyParameter(key));
    }

    private static AlgorithmIdentifier buildAlgId(ASN1ObjectIdentifier identifier)
    {
        return new AlgorithmIdentifier(identifier, DERNull.INSTANCE);
    }

    private static class KeyPairWithSubjectPublicKeyInfo
    {
        private KeyPair keypair;
        private SubjectPublicKeyInfo subjectPublicKeyInfo;

        public KeyPairWithSubjectPublicKeyInfo(KeyPair keypair,
                SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            super();
            this.keypair = keypair;
            this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        }

        public KeyPair getKeypair()
        {
            return keypair;
        }

        public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
        {
            return subjectPublicKeyInfo;
        }
    }

     static class KeyAndCertPair
     {
         private final X509CertificateHolder cert;
         private final X509Certificate jceCert;
         private final PrivateKey key;

         KeyAndCertPair(X509CertificateHolder cert, PrivateKey key)
         throws CertificateParsingException
         {
             this.cert = cert;
             this.key = key;
             // Due to bug in BC we must reparse the certificate from ByteArray
             org.bouncycastle.asn1.x509.Certificate cert2;
            try
            {
                cert2 = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());
            } catch (IOException e)
            {
                throw new CertificateParsingException(e);
            }
             this.jceCert = new X509CertificateObject(cert2);
         }

        public X509CertificateHolder getCert()
        {
            return cert;
        }

        public Certificate getJceCert()
        {
            return jceCert;
        }

        public PrivateKey getKey()
        {
            return key;
        }
     }

     public static class ECDSAIdentityGenerator extends P12KeypairGenerator
     {
         private String curveName;
         private ASN1ObjectIdentifier curveOid;

         public ECDSAIdentityGenerator(String curveNameOrOid, char[] password,
                 String subject)
         throws Exception
         {
             super(password, subject);

             boolean isOid;
             try
             {
                 new ASN1ObjectIdentifier(curveNameOrOid);
                 isOid = true;
             }catch(Exception e)
             {
                 isOid = false;
             }

             if(isOid)
             {
                 this.curveOid = new ASN1ObjectIdentifier(curveNameOrOid);
                 this.curveName = getCurveName(this.curveOid);
             }
             else
             {
                 this.curveName = curveNameOrOid;
                 this.curveOid = getCurveOID(this.curveName);
                 if(this.curveOid == null)
                 {
                     throw new IllegalArgumentException("No OID is defined for the curve " + this.curveName);
                 }
             }
         }

         @Override
         protected KeyPairWithSubjectPublicKeyInfo genKeypair()
         throws Exception
         {
             KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDSA", "BC");
             ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
             kpgen.initialize(spec);
             KeyPair kp = kpgen.generateKeyPair();

             AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                     this.curveOid);

             BCECPublicKey pub = (BCECPublicKey) kp.getPublic();

             ASN1OctetString p = (ASN1OctetString)new X9ECPoint(pub.getQ()).toASN1Primitive();
             SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algId, p.getOctets());

             return new KeyPairWithSubjectPublicKeyInfo(kp, subjectPublicKeyInfo);
         }

         @Override
         protected String getKeyAlgorithm()
         {
                return "ECDSA";
         }

         public static ASN1ObjectIdentifier getCurveOID(String curveName)
         {
             ASN1ObjectIdentifier curveOID = X962NamedCurves.getOID(curveName);
             if(curveOID == null)
             {
                 curveOID = SECNamedCurves.getOID(curveName);
             }
             if(curveOID == null)
             {
                 curveOID = TeleTrusTNamedCurves.getOID(curveName);
             }
             if(curveOID == null)
             {
                 curveOID = NISTNamedCurves.getOID(curveName);
             }

             return curveOID;
         }

         public static String getCurveName(ASN1ObjectIdentifier curveOID)
         {
             String curveName = X962NamedCurves.getName(curveOID);
             if(curveName == null)
             {
                 curveName = SECNamedCurves.getName(curveOID);
             }
             if(curveName == null)
             {
                 curveName = TeleTrusTNamedCurves.getName(curveOID);
             }
             if(curveName == null)
             {
                 curveName = NISTNamedCurves.getName(curveOID);
             }

             return curveName;
         }

     }

     public static class RSAIdentityGenerator extends P12KeypairGenerator
     {
         private int keysize;
         private BigInteger publicExponent;

         public RSAIdentityGenerator(
                 int keysize, BigInteger publicExponent,
                 char[] password, String subject)
         throws Exception
         {
             super(password, subject);

             this.keysize = keysize;
             this.publicExponent = publicExponent;
         }

         @Override
         protected KeyPairWithSubjectPublicKeyInfo genKeypair()
         throws Exception
         {
             KeyPairGenerator kpgen = KeyPairGenerator.getInstance("RSA", "BC");
             RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(keysize, publicExponent);
             kpgen.initialize(spec);
             KeyPair kp =  kpgen.generateKeyPair();

             SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                     KeyUtil.generatePublicKeyParameter(kp.getPublic()));
             return new KeyPairWithSubjectPublicKeyInfo(kp, spki);
         }

         @Override
         protected String getKeyAlgorithm()
         {
             return "RSA";
         }
    }

}
