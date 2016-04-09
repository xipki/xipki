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

package org.xipki.pki.scep.util;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.scep.crypto.KeyUsage;
import org.xipki.pki.scep.crypto.ScepHashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepUtil {
    private static final Logger LOG = LoggerFactory.getLogger(ScepUtil.class);

    private static final long MIN_IN_MS = 60L * 1000;
    private static final long DAY_IN_MS = 24L * 60 * MIN_IN_MS;

    private ScepUtil() {
    }

    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(
            final PublicKey publicKey)
    throws IOException {
        ParamUtil.requireNonNull("publicKey", publicKey);
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsaPubKey =
                    (java.security.interfaces.RSAPublicKey) publicKey;
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                            DERNull.INSTANCE),
                    new RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));
            return spki;
        } else {
            throw new IllegalArgumentException("unsupported public key " + publicKey);
        }
    }

    public static PKCS10CertificationRequest generateRequest(
            final PrivateKey privatekey,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDn,
            final Map<ASN1ObjectIdentifier, ASN1Encodable> attributes)
    throws OperatorCreationException {
        ParamUtil.requireNonNull("privatekey", privatekey);
        ParamUtil.requireNonNull("subjectPublicKeyInfo", subjectPublicKeyInfo);
        ParamUtil.requireNonNull("subjectDn", subjectDn);

        PKCS10CertificationRequestBuilder p10ReqBuilder =
                new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);

        if (attributes != null) {
            for (ASN1ObjectIdentifier attrType : attributes.keySet()) {
                p10ReqBuilder.addAttribute(attrType, attributes.get(attrType));
            }
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder(
                getSignatureAlgorithm(privatekey, ScepHashAlgoType.SHA1)).build(privatekey);
        return p10ReqBuilder.build(contentSigner);
    }

    public static PKCS10CertificationRequest generateRequest(
            final PrivateKey privatekey,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDn,
            final String challengePassword,
            final List<Extension> extensions)
    throws OperatorCreationException {
        ParamUtil.requireNonNull("privatekey", privatekey);
        ParamUtil.requireNonNull("subjectPublicKeyInfo", subjectPublicKeyInfo);
        ParamUtil.requireNonNull("subjectDn", subjectDn);

        Map<ASN1ObjectIdentifier, ASN1Encodable> attributes =
                new HashMap<ASN1ObjectIdentifier, ASN1Encodable>();

        if (challengePassword != null && !challengePassword.isEmpty()) {
            DERPrintableString asn1Pwd = new DERPrintableString(challengePassword);
            attributes.put(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, asn1Pwd);
        }

        if (extensions != null && !extensions.isEmpty()) {
            Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
            attributes.put(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, asn1Extensions);
        }

        return generateRequest(privatekey, subjectPublicKeyInfo, subjectDn, attributes);
    }

    public static X509Certificate generateSelfsignedCert(
            final CertificationRequest csr,
            final PrivateKey identityKey)
    throws CertificateException {
        ParamUtil.requireNonNull("csr", csr);
        return generateSelfsignedCert(csr.getCertificationRequestInfo().getSubject(),
                csr.getCertificationRequestInfo().getSubjectPublicKeyInfo(), identityKey);
    }

    public static X509Certificate generateSelfsignedCert(
            final X500Name subjectDn,
            final PublicKey pubKey,
            final PrivateKey identityKey)
    throws CertificateException {
        SubjectPublicKeyInfo pubKeyInfo;
        try {
            pubKeyInfo = createSubjectPublicKeyInfo(pubKey);
        } catch (IOException ex) {
            throw new CertificateException(ex.getMessage(), ex);
        }
        return generateSelfsignedCert(subjectDn, pubKeyInfo, identityKey);
    }

    public static X509Certificate generateSelfsignedCert(
            final X500Name subjectDn,
            final SubjectPublicKeyInfo pubKeyInfo,
            final PrivateKey identityKey)
    throws CertificateException {
        ParamUtil.requireNonNull("subjectDn", subjectDn);
        ParamUtil.requireNonNull("pubKeyInfo", pubKeyInfo);
        ParamUtil.requireNonNull("identityKey", identityKey);

        Date notBefore = new Date(System.currentTimeMillis() - 5 * MIN_IN_MS);
        Date notAfter = new Date(notBefore.getTime() + 30 * DAY_IN_MS);

        X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
                subjectDn, BigInteger.ONE, notBefore, notAfter, subjectDn,
                pubKeyInfo);

        X509KeyUsage ku = new X509KeyUsage(
                    X509KeyUsage.digitalSignature
                    | X509KeyUsage.dataEncipherment
                    | X509KeyUsage.keyAgreement
                    | X509KeyUsage.keyEncipherment);
        try {
            certGenerator.addExtension(Extension.keyUsage, true, ku);
        } catch (CertIOException ex) {
            throw new CertificateException(
                    "could not generate self-signed certificate: " + ex.getMessage(), ex);
        }

        String sigAlgorithm = ScepUtil.getSignatureAlgorithm(identityKey, ScepHashAlgoType.SHA1);
        ContentSigner contentSigner;
        try {
            contentSigner = new JcaContentSignerBuilder(sigAlgorithm).build(identityKey);
        } catch (OperatorCreationException ex) {
            throw new CertificateException("error whilc creating signer", ex);
        }

        Certificate asn1Cert = certGenerator.build(contentSigner).toASN1Structure();
        return new X509CertificateObject(asn1Cert);
    } // method generateSelfsignedCert

    /**
     * The first one is a non-CA certificate if there exists one non-CA certificate.
     */
    public static List<X509Certificate> getCertsFromSignedData(
            final SignedData signedData)
    throws CertificateException {
        ParamUtil.requireNonNull("signedData", signedData);
        ASN1Set set = signedData.getCertificates();
        if (set == null) {
            return Collections.emptyList();
        }

        final int n = set.size();
        if (n == 0) {
            return Collections.emptyList();
        }

        List<X509Certificate> certs = new LinkedList<X509Certificate>();

        X509Certificate eeCert = null;
        for (int i = 0; i < n; i++) {
            X509Certificate cert;
            try {
                Certificate asn1Cert = Certificate.getInstance(set.getObjectAt(i));
                cert = new X509CertificateObject(asn1Cert);
            } catch (IllegalArgumentException ex) {
                throw new CertificateException(ex);
            }

            if (eeCert == null && cert.getBasicConstraints() == -1) {
                eeCert = cert;
            } else {
                certs.add(cert);
            }
        }

        if (eeCert != null) {
            certs.add(0, eeCert);
        }

        return certs;
    } // method getCertsFromSignedData

    public static X509CRL getCrlFromPkiMessage(
            final SignedData signedData)
    throws CRLException {
        ParamUtil.requireNonNull("signedData", signedData);
        ASN1Set set = signedData.getCRLs();
        if (set == null || set.size() == 0) {
            return null;
        }

        try {
            CertificateList cl = CertificateList.getInstance(set.getObjectAt(0));
            return new X509CRLObject(cl);
        } catch (IllegalArgumentException ex) {
            throw new CRLException(ex);
        }
    }

    public static String getSignatureAlgorithm(
            final PrivateKey key,
            final ScepHashAlgoType hashAlgo) {
        ParamUtil.requireNonNull("key", key);
        ParamUtil.requireNonNull("hashAlgo", hashAlgo);
        String algorithm = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algorithm)) {
            return hashAlgo.getName() + "withRSA";
        } else {
            throw new UnsupportedOperationException(
                    "getSignatureAlgorithm() for non-RSA is not supported yet.");
        }
    }

    public static X509Certificate parseCert(
            final byte[] certBytes)
    throws IOException, CertificateException {
        ParamUtil.requireNonNull("certBytes", certBytes);
        return parseCert(new ByteArrayInputStream(certBytes));
    }

    private static X509Certificate parseCert(
            final InputStream certStream)
    throws IOException, CertificateException {
        ParamUtil.requireNonNull("certStream", certStream);
        CertificateFactory certFact;
        try {
            certFact = CertificateFactory.getInstance("X.509", "BC");
        } catch (NoSuchProviderException ex) {
            throw new IOException("NoSuchProviderException: " + ex.getMessage());
        }

        return (X509Certificate) certFact.generateCertificate(certStream);
    }

    private static byte[] extractSki(
            final X509Certificate cert)
    throws CertificateEncodingException {
        byte[] extValue = getCoreExtValue(cert, Extension.subjectKeyIdentifier);
        if (extValue == null) {
            return null;
        }

        try {
            return ASN1OctetString.getInstance(extValue).getOctets();
        } catch (IllegalArgumentException ex) {
            throw new CertificateEncodingException(ex.getMessage());
        }
    }

    private static byte[] extractAki(
            final X509Certificate cert)
    throws CertificateEncodingException {
        byte[] extValue = getCoreExtValue(cert, Extension.authorityKeyIdentifier);
        if (extValue == null) {
            return null;
        }

        try {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extValue);
            return aki.getKeyIdentifier();
        } catch (IllegalArgumentException ex) {
            throw new CertificateEncodingException(
                    "invalid extension AuthorityKeyIdentifier: " + ex.getMessage());
        }
    }

    public static boolean hasKeyusage(
            final X509Certificate cert,
            final KeyUsage usage) {
        boolean[] keyusage = cert.getKeyUsage();
        if (keyusage != null && keyusage.length > usage.getBit()) {
            return keyusage[usage.getBit()];
        }
        return false;
    }

    private static byte[] getCoreExtValue(
            final X509Certificate cert,
            final ASN1ObjectIdentifier type)
    throws CertificateEncodingException {
        ParamUtil.requireNonNull("cert", cert);
        ParamUtil.requireNonNull("type", type);
        byte[] fullExtValue = cert.getExtensionValue(type.getId());
        if (fullExtValue == null) {
            return null;
        }
        try {
            return ASN1OctetString.getInstance(fullExtValue).getOctets();
        } catch (IllegalArgumentException ex) {
            throw new CertificateEncodingException("invalid extension " + type.getId()
                    + ": " + ex.getMessage());
        }
    }

    public static boolean isSelfSigned(
            final X509Certificate cert) {
        ParamUtil.requireNonNull("cert", cert);
        boolean equals = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (!equals) {
            return false;
        }

        try {
            byte[] ski = extractSki(cert);
            byte[] aki = extractAki(cert);

            if (ski != null && aki != null) {
                return Arrays.equals(ski, aki);
            } else {
                return true;
            }
        } catch (CertificateEncodingException ex) {
            return false;
        }
    }

    public static boolean issues(
            final X509Certificate issuerCert,
            final X509Certificate cert)
    throws CertificateEncodingException {
        ParamUtil.requireNonNull("issuerCert", issuerCert);
        ParamUtil.requireNonNull("cert", cert);
        boolean isCa = issuerCert.getBasicConstraints() >= 0;
        if (!isCa) {
            return false;
        }

        boolean issues = issuerCert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (issues) {
            byte[] ski = extractSki(issuerCert);
            byte[] aki = extractAki(cert);
            if (ski != null) {
                issues = Arrays.equals(ski, aki);
            }
        }

        if (issues) {
            long issuerNotBefore = issuerCert.getNotBefore().getTime();
            long issuerNotAfter = issuerCert.getNotAfter().getTime();
            long notBefore = cert.getNotBefore().getTime();
            issues = notBefore <= issuerNotAfter && notBefore >= issuerNotBefore;
        }

        return issues;
    }

    public static String buildExceptionLogFormat(
            final String message) {
        return (message == null || message.isEmpty())
                ? "{}: {}"
                : message + ", {}: {}";
    }

    public static ASN1ObjectIdentifier extractDigesetAlgorithmIdentifier(
            final String sigOid,
            final byte[] sigParams)
    throws NoSuchAlgorithmException {
        ParamUtil.requireNonBlank("sigOid", sigOid);

        ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier(sigOid);

        ASN1ObjectIdentifier digestAlgOid;
        if (PKCSObjectIdentifiers.md5WithRSAEncryption.equals(algOid)) {
            digestAlgOid = PKCSObjectIdentifiers.md5;
        } else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid)) {
            digestAlgOid = X509ObjectIdentifiers.id_SHA1;
        } else if (PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid)) {
            digestAlgOid = NISTObjectIdentifiers.id_sha224;
        } else if (PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid)) {
            digestAlgOid = NISTObjectIdentifiers.id_sha256;
        } else if (PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid)) {
            digestAlgOid = NISTObjectIdentifiers.id_sha384;
        } else if (PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid)) {
            digestAlgOid = NISTObjectIdentifiers.id_sha512;
        } else if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid)) {
            RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigParams);
            digestAlgOid = param.getHashAlgorithm().getAlgorithm();
        } else {
            throw new NoSuchAlgorithmException("unknown signature algorithm" + algOid.getId());
        }

        return digestAlgOid;
    }

    public static ASN1Encodable getFirstAttrValue(
            final AttributeTable attrs,
            final ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("attrs", attrs);
        ParamUtil.requireNonNull("type", type);
        Attribute attr = attrs.get(type);
        if (attr == null) {
            return null;
        }
        ASN1Set set = attr.getAttrValues();
        return (set.size() == 0)
                ? null
                : set.getObjectAt(0);
    }

    public static byte[] read(
            final InputStream in)
    throws IOException {
        ParamUtil.requireNonNull("in", in);
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = in.read(buffer)) != -1) {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally {
            try {
                in.close();
            } catch (IOException ex) {
                LOG.error("could not close stream: {}", ex.getMessage());
            }
        }
    }

    public static void addCmsCertSet(
            final CMSSignedDataGenerator generator,
            final X509Certificate[] cmsCertSet)
    throws CertificateEncodingException, CMSException {
        if (cmsCertSet == null || cmsCertSet.length == 0) {
            return;
        }
        ParamUtil.requireNonNull("geneator", generator);
        Collection<X509Certificate> certColl = new LinkedList<X509Certificate>();
        for (X509Certificate m : cmsCertSet) {
            certColl.add(m);
        }

        JcaCertStore certStore = new JcaCertStore(certColl);
        generator.addCertificates(certStore);
    }

}
