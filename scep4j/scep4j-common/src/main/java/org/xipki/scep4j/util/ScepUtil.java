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

package org.xipki.scep4j.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.scep4j.crypto.HashAlgoType;
import org.xipki.scep4j.crypto.KeyUsage;
import org.xipki.scep4j.exception.MessageDecodingException;

/**
 * @author Lijun Liao
 */

public class ScepUtil
{
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(
            final PublicKey publicKey)
    throws IOException
    {
        if (publicKey instanceof java.security.interfaces.RSAPublicKey)
        {
            java.security.interfaces.RSAPublicKey rsaPubKey =
                    (java.security.interfaces.RSAPublicKey) publicKey;
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                            DERNull.INSTANCE),
                    new RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));
            return spki;
        } else
        {
            throw new IllegalArgumentException("unsupported public key  " + publicKey);
        }
    }

    public static PKCS10CertificationRequest generateRequest(
            final PrivateKey privatekey,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDN,
            final Map<ASN1ObjectIdentifier, ASN1Encodable> attributes)
    throws OperatorCreationException
    {
        PKCS10CertificationRequestBuilder p10ReqBuilder =
                new PKCS10CertificationRequestBuilder(subjectDN, subjectPublicKeyInfo);

        if (attributes != null)
        {
            for (ASN1ObjectIdentifier attrType : attributes.keySet())
            {
                p10ReqBuilder.addAttribute(attrType, attributes.get(attrType));
            }
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder(
                getSignatureAlgorithm(privatekey, HashAlgoType.SHA1)).build(privatekey);
        return p10ReqBuilder.build(contentSigner);
    }

    public static PKCS10CertificationRequest generateRequest(
            final PrivateKey privatekey,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDN,
            final String challengePassword,
            final List<Extension> extensions)
    throws OperatorCreationException
    {
        Map<ASN1ObjectIdentifier, ASN1Encodable> attributes =
                new HashMap<ASN1ObjectIdentifier, ASN1Encodable>();

        if (challengePassword != null && challengePassword.isEmpty() == false)
        {
            DERPrintableString asn1Pwd = new DERPrintableString(challengePassword);
            attributes.put(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, asn1Pwd);
        }

        if (extensions != null && extensions.isEmpty() == false)
        {
            Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
            attributes.put(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, asn1Extensions);
        }

        return generateRequest(privatekey, subjectPublicKeyInfo, subjectDN, attributes);
    }

    public static X509Certificate generateSelfsignedCert(
            final CertificationRequest csr,
            final PrivateKey identityKey)
    throws CertificateException
    {
        return generateSelfsignedCert(csr.getCertificationRequestInfo().getSubject(),
                csr.getCertificationRequestInfo().getSubjectPublicKeyInfo(), identityKey);
    }

    public static X509Certificate generateSelfsignedCert(
            final X500Name subjectDN,
            final PublicKey pubKey,
            final PrivateKey identityKey)
    throws CertificateException
    {
        SubjectPublicKeyInfo pubKeyInfo;
        try
        {
            pubKeyInfo = createSubjectPublicKeyInfo(pubKey);
        } catch (IOException e)
        {
            throw new CertificateException(e.getMessage(), e);
        }
        return generateSelfsignedCert(subjectDN, pubKeyInfo, identityKey);
    }

    public static X509Certificate generateSelfsignedCert(
            final X500Name subjectDN,
            final SubjectPublicKeyInfo pubKeyInfo,
            final PrivateKey identityKey)
    throws CertificateException
    {
        final long MIN_IN_MS = 60L * 1000;
        final long DAY_IN_MS = 24L * 60 * MIN_IN_MS;

        Date notBefore = new Date(System.currentTimeMillis() - 5 * MIN_IN_MS);
        Date notAfter = new Date(notBefore.getTime() + 30 * DAY_IN_MS);

        X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
                subjectDN, BigInteger.ONE, notBefore, notAfter, subjectDN,
                pubKeyInfo);

        X509KeyUsage ku = new X509KeyUsage(
                    X509KeyUsage.digitalSignature
                    | X509KeyUsage.dataEncipherment
                    | X509KeyUsage.keyAgreement
                    | X509KeyUsage.keyEncipherment);
        try
        {
            certGenerator.addExtension(Extension.keyUsage, true, ku);
        } catch (CertIOException e)
        {
            throw new CertificateException(
                    "error while generating self-signed certificate: " + e.getMessage(), e);
        }

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(identityKey, HashAlgoType.SHA1);
        ContentSigner contentSigner;
        try
        {
            contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(identityKey);
        } catch (OperatorCreationException e)
        {
            throw new CertificateException("error whilc creating signer", e);
        }

        Certificate asn1Cert = certGenerator.build(contentSigner).toASN1Structure();
        return new X509CertificateObject(asn1Cert);
    }

    /**
     * The first one is a non-CA certificate if there exists one non-CA certificate
     * @param certBytes
     * @return
     * @throws MessageDecodingException
     */
    public static List<X509Certificate> getCertsFromSignedData(
            final SignedData signedData)
    throws CertificateException
    {
        ASN1Set set = signedData.getCertificates();
        int n;
        if (set == null || (n = set.size()) == 0)
        {
            return Collections.emptyList();
        }

        List<X509Certificate> certs = new LinkedList<X509Certificate>();

        X509Certificate eeCert = null;
        for (int i = 0; i < n; i++)
        {
            X509Certificate cert;
            try
            {
                Certificate asn1Cert = Certificate.getInstance(set.getObjectAt(i));
                cert = new X509CertificateObject(asn1Cert);
            } catch (IllegalArgumentException e)
            {
                throw new CertificateException(e);
            }

            if (eeCert == null && cert.getBasicConstraints() == -1)
            {
                eeCert = cert;
            }
            else
            {
                certs.add(cert);
            }
        }

        if (eeCert != null)
        {
            certs.add(0, eeCert);
        }

        return certs;
    }

    public static X509CRL getCRLFromPkiMessage(
            final SignedData signedData)
    throws CRLException
    {
        ASN1Set set = signedData.getCRLs();
        if (set == null || set.size() == 0)
        {
            return null;
        }

        try
        {
            CertificateList cl = CertificateList.getInstance(set.getObjectAt(0));
            return new X509CRLObject(cl);
        } catch (IllegalArgumentException e)
        {
            throw new CRLException(e);
        }
    }

    public static String getSignatureAlgorithm(
            final PrivateKey key,
            final HashAlgoType hashAlgo)
    {
        String algorithm = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algorithm))
        {
            return hashAlgo.getName() + "withRSA";
        } else
        {
            throw new UnsupportedOperationException(
                    "getSignatureAlgorithm() for non-RSA is not supported yet.");
        }
    }

    public static X509Certificate parseCert(
            final byte[] certBytes)
    throws IOException, CertificateException
    {
        return parseCert(new ByteArrayInputStream(certBytes));
    }

    private static X509Certificate parseCert(
            final InputStream certStream)
    throws IOException, CertificateException
    {
        CertificateFactory certFact;
        try
        {
            certFact = CertificateFactory.getInstance("X.509", "BC");
        } catch (NoSuchProviderException e)
        {
            throw new IOException("NoSuchProviderException: " + e.getMessage());
        }

        return (X509Certificate) certFact.generateCertificate(certStream);
    }

    private static byte[] extractSKI(
            final X509Certificate cert)
    throws CertificateEncodingException
    {
        byte[] extValue = getCoreExtValue(cert, Extension.subjectKeyIdentifier);
        if (extValue == null)
        {
            return null;
        }

        try
        {
            return ASN1OctetString.getInstance(extValue).getOctets();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException(e.getMessage());
        }
    }

    private static byte[] extractAKI(
            final X509Certificate cert)
    throws CertificateEncodingException
    {
        byte[] extValue = getCoreExtValue(cert, Extension.authorityKeyIdentifier);
        if (extValue == null)
        {
            return null;
        }

        try
        {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extValue);
            return aki.getKeyIdentifier();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException(
                    "invalid extension AuthorityKeyIdentifier: " + e.getMessage());
        }
    }

    public static boolean hasKeyusage(
            final X509Certificate cert,
            final KeyUsage usage)
    {
        boolean[] keyusage = cert.getKeyUsage();
        if (keyusage != null && keyusage.length > usage.getBit())
        {
            return keyusage[usage.getBit()];
        }
        return false;
    }

    private static byte[] getCoreExtValue(
            final X509Certificate cert,
            final ASN1ObjectIdentifier type)
    throws CertificateEncodingException
    {
        byte[] fullExtValue = cert.getExtensionValue(type.getId());
        if (fullExtValue == null)
        {
            return null;
        }
        try
        {
            return ASN1OctetString.getInstance(fullExtValue).getOctets();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException("invalid extension " + type.getId()
                    + ": " + e.getMessage());
        }
    }

    public static boolean isSelfSigned(
            final X509Certificate cert)
    {
        boolean equals = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (equals == false)
        {
            return false;
        }

        try
        {
            byte[] ski = extractSKI(cert);
            byte[] aki = extractAKI(cert);

            if (ski != null && aki != null)
            {
                return Arrays.equals(ski, aki);
            } else
            {
                return true;
            }
        } catch (CertificateEncodingException e)
        {
            return false;
        }
    }

    public static boolean issues(
            final X509Certificate issuerCert,
            final X509Certificate cert)
    throws CertificateEncodingException
    {
        boolean isCA = issuerCert.getBasicConstraints() >= 0;
        if (isCA == false)
        {
            return false;
        }

        boolean issues = issuerCert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (issues)
        {
            byte[] ski = extractSKI(issuerCert);
            byte[] aki = extractAKI(cert);
            if (ski != null)
            {
                issues = Arrays.equals(ski, aki);
            }
        }

        if (issues)
        {
            long issuerNotBefore = issuerCert.getNotBefore().getTime();
            long issuerNotAfter = issuerCert.getNotAfter().getTime();
            long notBefore = cert.getNotBefore().getTime();
            issues = notBefore <= issuerNotAfter && notBefore >= issuerNotBefore;
        }

        return issues;
    }

    public static String buildExceptionLogFormat(
            final String message)
    {
        return (message == null || message.isEmpty())
                ? "{}: {}"
                : message + ", {}: {}";
    }

    static public ASN1ObjectIdentifier extractDigesetAlgorithmIdentifier(
            final String sigOid,
            final byte[] sigParams)
    throws NoSuchAlgorithmException
    {
        ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier(sigOid);

        ASN1ObjectIdentifier digestAlgOid;
        if (PKCSObjectIdentifiers.md5WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = PKCSObjectIdentifiers.md5;
        }
        else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if (PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha224;
        }
        else if (PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha256;
        }
        else if (PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha384;
        }
        else if (PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha512;
        }
        else if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid))
        {
            RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigParams);
            digestAlgOid = param.getHashAlgorithm().getAlgorithm();
        }
        else
        {
            throw new NoSuchAlgorithmException("unknown signature algorithm" + algOid.getId());
        }

        return digestAlgOid;
    }

    public static ASN1Encodable getFirstAttrValue(
            final AttributeTable attrs,
            final ASN1ObjectIdentifier type)
    {
        Attribute attr = attrs.get(type);
        if (attr == null)
        {
            return null;
        }
        ASN1Set set = attr.getAttrValues();
        return (set.size() == 0)
                ? null
                : set.getObjectAt(0);
    }

    public static byte[] read(
            final InputStream in)
    throws IOException
    {
        try
        {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = in.read(buffer)) != -1)
            {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally
        {
            if (in != null)
            {
                try
                {
                    in.close();
                } catch (IOException e)
                {
                }
            }
        }
    }

    public static void addCmsCertSet(
            final CMSSignedDataGenerator generator,
            final X509Certificate[] cmsCertSet)
    throws CertificateEncodingException, CMSException
    {
        if (cmsCertSet == null || cmsCertSet.length == 0)
        {
            return;
        }

        Collection<X509Certificate> certColl = new LinkedList<X509Certificate>();
        for (X509Certificate m : cmsCertSet)
        {
            certColl.add(m);
        }

        JcaCertStore certStore = new JcaCertStore(certColl);
        generator.addCertificates(certStore);
    }

    public static boolean isBlank(
            final String s)
    {
        return s == null || s.isEmpty();
    }

    public static boolean isNotBlank(
            final String s)
    {
        return s != null && s.isEmpty() == false;
    }

}
