/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.security.p11.iaik;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11KeypairGenerator
{
    public static final long YEAR = 365L * 24 * 60 * 60 * 1000; // milliseconds of one year

    private final SecurityFactory securityFactory;
    public P11KeypairGenerator(SecurityFactory securityFacotry)
    {
        ParamChecker.assertNotNull("securityFactory", securityFacotry);
        this.securityFactory = securityFacotry;
    }

    private IaikExtendedSlot getSlot(String pkcs11ModuleName, P11SlotIdentifier slotId)
    throws SignerException
    {
        // this call initialize the IaikExtendedModule
        P11CryptService p11CryptService = securityFactory.getP11CryptService(pkcs11ModuleName);
        if(p11CryptService == null)
        {
            throw new SignerException("Could not initialize P11CryptService " + pkcs11ModuleName);
        }

        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(pkcs11ModuleName);
        if(module == null)
        {
            throw new SignerException("P11KeypairGenerator only works with P11CryptServiceFactory " +
                    IaikP11CryptServiceFactory.class.getName());
        }

        IaikExtendedSlot slot = module.getSlot(slotId);
        if(slot == null)
        {
            throw new SignerException("Could not find any slot with id " + slotId);
        }
        return slot;
    }

    public P11KeypairGenerationResult generateRSAKeypairAndCert(
            String p11ModuleName, P11SlotIdentifier slotId,
            int keySize, BigInteger publicExponent,
            String label, String subject,
            Integer keyUsage,
            List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception
    {
        ParamChecker.assertNotEmpty("label", label);

        if (keySize < 1024)
        {
            throw new IllegalArgumentException("Keysize not allowed: " + keySize);
        }

        if(keySize % 1024 != 0)
        {
            throw new IllegalArgumentException("Key size is not multiple of 1024: " + keySize);
        }

        IaikExtendedSlot slot = getSlot(p11ModuleName, slotId);

        Session session = slot.borrowWritableSession();
        try
        {
            if(IaikP11Util.labelExists(session, label))
            {
                throw new IllegalArgumentException("Label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyID(session);

            PrivateKeyAndPKInfo privateKeyAndPKInfo = generateRSAKeyPair(
                    session,
                    keySize, publicExponent, id, label);

            AlgorithmIdentifier signatureAlgId = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);

            X509CertificateHolder certificate = generateCertificate(session,
                    id, label, subject,
                    signatureAlgId, privateKeyAndPKInfo,
                    keyUsage, extendedKeyusage);
            return new P11KeypairGenerationResult(id, label, certificate);
        }
        finally
        {
            slot.returnWritableSession(session);
        }
    }

    private PrivateKeyAndPKInfo generateRSAKeyPair(
            Session session,
            int keySize, BigInteger publicExponent,
            byte[] id, String label)
    throws Exception
    {
        if(publicExponent == null)
        {
            publicExponent = BigInteger.valueOf(65537);
        }

        RSAPrivateKey privateKey = new RSAPrivateKey();
        RSAPublicKey publicKey = new RSAPublicKey();

        setKeyAttributes(id, label, PKCS11Constants.CKK_RSA, privateKey, publicKey);

        publicKey.getModulusBits().setLongValue((long) keySize);
        publicKey.getPublicExponent().setByteArrayValue(publicExponent.toByteArray());

        KeyPair kp = session.generateKeyPair(
                Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN), publicKey, privateKey);

        publicKey = (RSAPublicKey) kp.getPublicKey();

        BigInteger modulus = new BigInteger(1, publicKey.getModulus().getByteArrayValue());
        publicExponent = new BigInteger(1, publicKey.getPublicExponent().getByteArrayValue());
        RSAKeyParameters keyParams = new RSAKeyParameters(false, modulus, publicExponent);
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParams);

        return new PrivateKeyAndPKInfo((RSAPrivateKey) kp.getPrivateKey(), pkInfo);
    }

    public P11KeypairGenerationResult generateDSAKeypairAndCert(
            String p11ModuleName, P11SlotIdentifier slotId,
            int pLength, int qLength, String label, String subject, Integer keyUsage,
            List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception
    {
        ParamChecker.assertNotEmpty("label", label);

        if (pLength < 1024)
        {
            throw new IllegalArgumentException("Keysize not allowed: " + pLength);
        }

        if(pLength % 1024 != 0)
        {
            throw new IllegalArgumentException("Key size is not multiple of 1024: " + pLength);
        }

        IaikExtendedSlot slot = getSlot(p11ModuleName, slotId);

        Session session = slot.borrowWritableSession();
        try
        {
            if(IaikP11Util.labelExists(session, label))
            {
                throw new IllegalArgumentException("Label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyID(session);

            PrivateKeyAndPKInfo privateKeyAndPKInfo = generateDSAKeyPair(session, pLength, qLength, id, label);
            AlgorithmIdentifier signatureAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.dsa_with_sha256);

            X509CertificateHolder certificate = generateCertificate(session,
                    id, label, subject,
                    signatureAlgId, privateKeyAndPKInfo,
                    keyUsage, extendedKeyusage);
            return new P11KeypairGenerationResult(id, label, certificate);
        }
        finally
        {
            slot.returnWritableSession(session);
        }
    }

    private PrivateKeyAndPKInfo generateDSAKeyPair(
            Session session, int pLength, int qLength, byte[] id, String label)
    throws Exception
    {
        DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
        DSAParameterGenerationParameters genParams = new DSAParameterGenerationParameters(
                pLength, qLength, 80, new SecureRandom());
        paramGen.init(genParams);
        DSAParameters dsaParams = paramGen.generateParameters();

        DSAPrivateKey privateKey = new DSAPrivateKey();
        DSAPublicKey publicKey = new DSAPublicKey();

        setKeyAttributes(id, label, PKCS11Constants.CKK_DSA, privateKey, publicKey);

        publicKey.getPrime().setByteArrayValue(dsaParams.getP().toByteArray());
        publicKey.getSubprime().setByteArrayValue(dsaParams.getQ().toByteArray());
        publicKey.getBase().setByteArrayValue(dsaParams.getG().toByteArray());

        KeyPair kp = session.generateKeyPair(
                Mechanism.get(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN), publicKey, privateKey);

        publicKey = (DSAPublicKey) kp.getPublicKey();
        BigInteger value = new BigInteger(1, publicKey.getValue().getByteArrayValue());

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(dsaParams.getP()));
        v.add(new ASN1Integer(dsaParams.getQ()));
        v.add(new ASN1Integer(dsaParams.getG()));
        ASN1Sequence dssParams = new DERSequence(v);

        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dssParams),
                new ASN1Integer(value));

        return new PrivateKeyAndPKInfo((DSAPrivateKey) kp.getPrivateKey(), pkInfo);
    }

    private static void setKeyAttributes(
            byte[] id, String label, long keyType,
            PrivateKey privateKey, PublicKey publicKey)
    {
        if(privateKey != null)
        {
            privateKey.getId().setByteArrayValue(id);
            privateKey.getToken().setBooleanValue(true);
            privateKey.getLabel().setCharArrayValue(label.toCharArray());
            privateKey.getKeyType().setLongValue(keyType);
            privateKey.getSign().setBooleanValue(true);
            privateKey.getPrivate().setBooleanValue(true);
            privateKey.getSensitive().setBooleanValue(true);
        }

        if(publicKey != null)
        {
            publicKey.getId().setByteArrayValue(id);
            publicKey.getToken().setBooleanValue(true);
            publicKey.getLabel().setCharArrayValue(label.toCharArray());
            publicKey.getKeyType().setLongValue(keyType);
            publicKey.getVerify().setBooleanValue(true);
            publicKey.getModifiable().setBooleanValue(Boolean.TRUE);
        }
    }

    public P11KeypairGenerationResult generateECDSAKeypairAndCert(
            String p11ModuleName, P11SlotIdentifier slotId,
            String curveNameOrOid, String label, String subject,
            Integer keyUsage,
            List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception
    {
        ASN1ObjectIdentifier curveId = getCurveId(curveNameOrOid);
        if(curveId == null)
        {
            throw new IllegalArgumentException("Unknown curve " + curveNameOrOid);
        }

        X9ECParameters ecParams =  ECNamedCurveTable.getByOID(curveId);
        if(ecParams == null)
        {
            throw new IllegalArgumentException("Unknown curve " + curveNameOrOid);
        }

        IaikExtendedSlot slot = getSlot(p11ModuleName, slotId);

        Session session = slot.borrowWritableSession();
        try
        {
            if(IaikP11Util.labelExists(session, label))
            {
                throw new IllegalArgumentException("Label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyID(session);

            PrivateKeyAndPKInfo privateKeyAndPKInfo = generateECDSAKeyPair(
                    session, curveId, ecParams, id, label);

            int keyBitLength = ecParams.getN().bitLength();

            ASN1ObjectIdentifier sigAlgOid;
            if(keyBitLength > 384)
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            }
            else if(keyBitLength > 256)
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            }
            else if(keyBitLength > 224)
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            }
            else if(keyBitLength > 160)
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            }
            else
            {
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            }

            X509CertificateHolder certificate = generateCertificate(session,
                    id, label, subject,
                    new AlgorithmIdentifier(sigAlgOid, DERNull.INSTANCE),
                    privateKeyAndPKInfo,
                    keyUsage,
                    extendedKeyusage);

            return new P11KeypairGenerationResult(id, label, certificate);
        }finally
        {
            slot.returnWritableSession(session);
        }
    }

    private static ASN1ObjectIdentifier getCurveId(String curveNameOrOid)
    {
        ASN1ObjectIdentifier curveId;

        try
        {
            curveId = new ASN1ObjectIdentifier(curveNameOrOid);
            return curveId;
        } catch(Exception e)
        {
        }

        curveId = X962NamedCurves.getOID(curveNameOrOid);

        if (curveId == null)
        {
            curveId = SECNamedCurves.getOID(curveNameOrOid);
        }

        if (curveId == null)
        {
            curveId = TeleTrusTNamedCurves.getOID(curveNameOrOid);
        }

        if (curveId == null)
        {
            curveId = NISTNamedCurves.getOID(curveNameOrOid);
        }

        return curveId;
    }

    private PrivateKeyAndPKInfo generateECDSAKeyPair(
            Session session,
            ASN1ObjectIdentifier curveId, X9ECParameters ecParams,
            byte[] id, String label)
    throws Exception
    {
        KeyPair kp = null;

        try
        {
            kp = generateNamedECDSAKeyPair(session, curveId, id, label);
        }catch(TokenException e)
        {
            kp = generateSpecifiedECDSAKeyPair(session, curveId, ecParams, id, label);
        }

        ECDSAPublicKey publicKey = (ECDSAPublicKey) kp.getPublicKey();

        // build subjectPKInfo object
        byte[] pubPoint = publicKey.getEcPoint().getByteArrayValue();
        DEROctetString os = (DEROctetString)DEROctetString.fromByteArray(pubPoint);

        AlgorithmIdentifier keyAlgID = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveId);
        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(keyAlgID, os.getOctets());
        return new PrivateKeyAndPKInfo((ECDSAPrivateKey) kp.getPrivateKey(), pkInfo);
    }

    private KeyPair generateNamedECDSAKeyPair(
            Session session, ASN1ObjectIdentifier curveId, byte[] id, String label)
    throws TokenException, IOException
    {
        ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
        ECDSAPublicKey publicKeyTemplate = new ECDSAPublicKey();
        setKeyAttributes(id, label, PKCS11Constants.CKK_ECDSA, privateKeyTemplate, publicKeyTemplate);

        byte[] ecdsaParamsBytes = curveId.getEncoded();
        publicKeyTemplate.getEcdsaParams().setByteArrayValue(ecdsaParamsBytes);

        return session.generateKeyPair(Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
                publicKeyTemplate, privateKeyTemplate);
    }

    private KeyPair generateSpecifiedECDSAKeyPair(
            Session session, ASN1ObjectIdentifier curveId, X9ECParameters ecParams, byte[] id, String label)
    throws TokenException, IOException
    {
        ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
        ECDSAPublicKey publicKeyTemplate = new ECDSAPublicKey();
        setKeyAttributes(id, label, PKCS11Constants.CKK_ECDSA, privateKeyTemplate, publicKeyTemplate);

        byte[] ecdsaParamsBytes = ecParams.getEncoded();
        publicKeyTemplate.getEcdsaParams().setByteArrayValue(ecdsaParamsBytes);

        KeyPair kp = session.generateKeyPair(Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
                publicKeyTemplate, privateKeyTemplate);

        return kp;
    }

    private X509CertificateHolder generateCertificate(
            Session session, byte[] id, String label, String subject,
            AlgorithmIdentifier signatureAlgId, PrivateKeyAndPKInfo privateKeyAndPkInfo,
            Integer keyUsage, List<ASN1ObjectIdentifier> extendedKeyUsage)
    throws Exception
    {
        BigInteger serialNumber = BigInteger.ONE;
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 20 * YEAR);

        X500Name x500Name_subject = new X500Name(subject);
        x500Name_subject = IoCertUtil.sortX509Name(x500Name_subject);

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(serialNumber));
        tbsGen.setSignature(signatureAlgId);
        tbsGen.setIssuer(x500Name_subject);
        tbsGen.setStartDate(new Time(startDate));
        tbsGen.setEndDate(new Time(endDate));
        tbsGen.setSubject(x500Name_subject);
        tbsGen.setSubjectPublicKeyInfo(privateKeyAndPkInfo.getPublicKeyInfo());

        List<Extension> extensions = new ArrayList<>(2);
        if(keyUsage == null)
        {
            keyUsage = KeyUsage.keyCertSign | KeyUsage.cRLSign |
                    KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        }
        extensions.add(new Extension(Extension.keyUsage, true,
                new DEROctetString(new KeyUsage(keyUsage))));

        if(extendedKeyUsage != null && extendedKeyUsage.isEmpty() == false)
        {
            KeyPurposeId[] kps = new KeyPurposeId[extendedKeyUsage.size()];

            int i = 0;
            for (ASN1ObjectIdentifier oid : extendedKeyUsage)
            {
                kps[i++] = KeyPurposeId.getInstance(oid);
            }

            extensions.add(new Extension(Extension.extendedKeyUsage, false,
                    new DEROctetString(new ExtendedKeyUsage(kps))));
        }

        Extensions paramX509Extensions = new Extensions(extensions.toArray(new Extension[0]));
        tbsGen.setExtensions(paramX509Extensions);

        TBSCertificate tbsCertificate = tbsGen.generateTBSCertificate();
        byte[] encodedTbsCertificate = tbsCertificate.getEncoded();
        byte[] signature = null;
        Digest digest = null;
        Mechanism sigMechanism = null;

        ASN1ObjectIdentifier sigAlgID = signatureAlgId.getAlgorithm();

        if (sigAlgID.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption))
        {
            sigMechanism = Mechanism.get(PKCS11Constants.CKM_SHA256_RSA_PKCS);
            session.signInit(sigMechanism, privateKeyAndPkInfo.getPrivateKey());
            signature = session.sign(encodedTbsCertificate);
        }
        else if (sigAlgID.equals(NISTObjectIdentifiers.dsa_with_sha256))
        {
            digest = new SHA256Digest();
            byte[] digestValue = new byte[digest.getDigestSize()];
            digest.update(encodedTbsCertificate, 0, encodedTbsCertificate.length);
            digest.doFinal(digestValue, 0);

            session.signInit(Mechanism.get(PKCS11Constants.CKM_DSA), privateKeyAndPkInfo.getPrivateKey());
            byte[] rawSignature = session.sign(digestValue);
            signature = convertToX962Signature(rawSignature);
        }
        else
        {
            if (sigAlgID.equals(X9ObjectIdentifiers.ecdsa_with_SHA1))
            {
                digest = new SHA1Digest();
            }
            else if (sigAlgID.equals(X9ObjectIdentifiers.ecdsa_with_SHA256))
            {
                digest = new SHA256Digest();
            }
            else if (sigAlgID.equals(X9ObjectIdentifiers.ecdsa_with_SHA384))
            {
                digest = new SHA384Digest();
            }
            else if (sigAlgID.equals(X9ObjectIdentifiers.ecdsa_with_SHA512))
            {
                digest = new SHA512Digest();
            }
            else
            {
                System.err.println("Unknown algorithm ID: " + sigAlgID.getId());
                return null;
            }

            byte[] digestValue = new byte[digest.getDigestSize()];
            digest.update(encodedTbsCertificate, 0, encodedTbsCertificate.length);
            digest.doFinal(digestValue, 0);

            session.signInit(Mechanism.get(PKCS11Constants.CKM_ECDSA), privateKeyAndPkInfo.getPrivateKey());
            byte[] rawSignature = session.sign(digestValue);
            signature = convertToX962Signature(rawSignature);
        }

        // build DER certificate
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCertificate);
        v.add(signatureAlgId);
        v.add(new DERBitString(signature));
        DERSequence cert = new DERSequence(v);

        // build and store PKCS#11 certificate object
        X509PublicKeyCertificate certTemp = new X509PublicKeyCertificate();
        certTemp.getToken().setBooleanValue(true);
        certTemp.getId().setByteArrayValue(id);
        certTemp.getLabel().setCharArrayValue(label.toCharArray());
        certTemp.getSubject().setByteArrayValue(x500Name_subject.getEncoded());
        certTemp.getIssuer().setByteArrayValue(x500Name_subject.getEncoded());
        certTemp.getSerialNumber().setByteArrayValue(serialNumber.toByteArray());
        certTemp.getValue().setByteArrayValue(cert.getEncoded());
        session.createObject(certTemp);

        return new X509CertificateHolder(Certificate.getInstance(cert));
    }

    private static byte[] convertToX962Signature(byte[] signature)
    throws IOException
    {
        int n = signature.length / 2;
        byte[] x = Arrays.copyOfRange(signature, 0, n);
        byte[] y = Arrays.copyOfRange(signature, n, 2*n);

        ASN1EncodableVector sigder = new ASN1EncodableVector();
        sigder.add(new ASN1Integer(
                new BigInteger(1, x)));
        sigder.add(new ASN1Integer(
                new BigInteger(1, y)));

        return new DERSequence(sigder).getEncoded();
    }

    private static class PrivateKeyAndPKInfo
    {
        private final PrivateKey privateKey;
        private final SubjectPublicKeyInfo publicKeyInfo;

        public PrivateKeyAndPKInfo(PrivateKey privateKey, SubjectPublicKeyInfo publicKeyInfo)
        {
            super();
            this.privateKey = privateKey;
            this.publicKeyInfo = IoCertUtil.toRfc3279Style(publicKeyInfo);
        }

        public PrivateKey getPrivateKey()
        {
            return privateKey;
        }

        public SubjectPublicKeyInfo getPublicKeyInfo()
        {
            return publicKeyInfo;
        }
    }
}
