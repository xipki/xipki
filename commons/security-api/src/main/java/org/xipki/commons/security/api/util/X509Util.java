/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.api.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.BadInputException;
import org.xipki.commons.security.api.FpIdCalculator;
import org.xipki.commons.security.api.KeyUsage;
import org.xipki.commons.security.api.ObjectIdentifiers;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509Util {

    private static CertificateFactory certFact;
    private static Object certFactLock = new Object();

    private X509Util() {
    }

    public static String getCommonName(
            final X500Principal name) {
        ParamUtil.requireNonNull("name", name);
        return getCommonName(X500Name.getInstance(name.getEncoded()));
    }

    public static String getCommonName(
            final X500Name name) {
        ParamUtil.requireNonNull("name", name);
        RDN[] rdns = name.getRDNs(ObjectIdentifiers.DN_CN);
        if (rdns != null && rdns.length > 0) {
            RDN rdn = rdns[0];
            AttributeTypeAndValue atv = null;
            if (rdn.isMultiValued()) {
                for (AttributeTypeAndValue m : rdn.getTypesAndValues()) {
                    if (m.getType().equals(ObjectIdentifiers.DN_CN)) {
                        atv = m;
                        break;
                    }
                }
            } else {
                atv = rdn.getFirst();
            }
            return (atv == null)
                    ? null
                    : rdnValueToString(atv.getValue());
        }
        return null;
    }

    public static X500Name reverse(
            final X500Name name) {
        ParamUtil.requireNonNull("name", name);
        RDN[] orig = name.getRDNs();
        int n = orig.length;
        RDN[] newRDN = new RDN[n];
        for (int i = 0; i < n; i++) {
            newRDN[i] = orig[n - 1 - i];
        }
        return new X500Name(newRDN);
    }

    public static X500Name sortX509Name(
            final X500Name name) {
        ParamUtil.requireNonNull("name", name);
        RDN[] requstedRDNs = name.getRDNs();

        List<RDN> rdns = new LinkedList<>();

        List<ASN1ObjectIdentifier> sortedDNs = ObjectIdentifiers.getForwardDNs();
        int size = sortedDNs.size();
        for (int i = 0; i < size; i++) {
            ASN1ObjectIdentifier type = sortedDNs.get(i);
            RDN[] thisRDNs = getRDNs(requstedRDNs, type);
            int n = (thisRDNs == null)
                    ? 0
                    : thisRDNs.length;
            if (n == 0) {
                continue;
            }

            for (RDN thisRDN : thisRDNs) {
                rdns.add(thisRDN);
            }
        }

        return new X500Name(rdns.toArray(new RDN[0]));
    }

    private static RDN[] getRDNs(
            final RDN[] rdns,
            final ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("rdns", rdns);
        ParamUtil.requireNonNull("type", type);
        List<RDN> ret = new ArrayList<>(1);
        for (int i = 0; i < rdns.length; i++) {
            RDN rdn = rdns[i];
            if (rdn.getFirst().getType().equals(type)) {
                ret.add(rdn);
            }
        }

        if (CollectionUtil.isEmpty(ret)) {
            return null;
        } else {
            return ret.toArray(new RDN[0]);
        }
    }

    public static X509Certificate parseCert(
            final String fileName)
    throws IOException, CertificateException {
        ParamUtil.requireNonNull("fileName", fileName);
        return parseCert(new File(IoUtil.expandFilepath(fileName)));
    }

    public static X509Certificate parseCert(
            final File file)
    throws IOException, CertificateException {
        ParamUtil.requireNonNull("file", file);
        FileInputStream in = new FileInputStream(IoUtil.expandFilepath(file));
        try {
            return parseCert(in);
        } finally {
            in.close();
        }
    }

    public static X509Certificate parseCert(
            final byte[] certBytes)
    throws IOException, CertificateException {
        ParamUtil.requireNonNull("certBytes", certBytes);
        return parseCert(new ByteArrayInputStream(certBytes));
    }

    public static X509Certificate parseBase64EncodedCert(
            final String base64EncodedCert)
    throws IOException, CertificateException {
        ParamUtil.requireNonNull("base64EncodedCert", base64EncodedCert);
        return parseCert(Base64.decode(base64EncodedCert));
    }

    public static X509Certificate parseCert(
            final InputStream certStream)
    throws IOException, CertificateException {
        ParamUtil.requireNonNull("certStream", certStream);
        synchronized (certFactLock) {
            if (certFact == null) {
                try {
                    certFact = CertificateFactory.getInstance("X.509", "BC");
                } catch (NoSuchProviderException ex) {
                    throw new IOException("NoSuchProviderException: " + ex.getMessage());
                }
            }
        }

        return (X509Certificate) certFact.generateCertificate(certStream);
    }

    public static X509CRL parseCrl(
            final String file)
    throws IOException, CertificateException, CRLException {
        ParamUtil.requireNonBlank("file", file);
        return parseCrl(new FileInputStream(IoUtil.expandFilepath(file)));
    }

    public static X509CRL parseCrl(
            final InputStream crlStream)
    throws IOException, CertificateException, CRLException {
        ParamUtil.requireNonNull("crlStream", crlStream);
        try {
            synchronized (certFactLock) {
                if (certFact == null) {
                    certFact = CertificateFactory.getInstance("X.509", "BC");
                }
                return (X509CRL) certFact.generateCRL(crlStream);
            }
        } catch (NoSuchProviderException ex) {
            throw new IOException("NoSuchProviderException: " + ex.getMessage());
        }
    }

    public static String getRfc4519Name(
            final X500Principal name) {
        ParamUtil.requireNonNull("name", name);
        return getRfc4519Name(X500Name.getInstance(name.getEncoded()));
    }

    public static String getRfc4519Name(
            final X500Name name) {
        ParamUtil.requireNonNull("name", name);
        return RFC4519Style.INSTANCE.toString(name);
    }

    /**
     * First canonicalized the name, and then compute the SHA-1 finger-print over the
     * canonicalized subject string.
     */
    public static long fpCanonicalizedName(
            final X500Principal prin) {
        ParamUtil.requireNonNull("prin", prin);
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return fpCanonicalizedName(x500Name);
    }

    public static long fpCanonicalizedName(
            final X500Name name) {
        ParamUtil.requireNonNull("name", name);
        String canonicalizedName = canonicalizName(name);
        byte[] encoded;
        try {
            encoded = canonicalizedName.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            encoded = canonicalizedName.getBytes();
        }
        return FpIdCalculator.hash(encoded);
    }

    public static String canonicalizName(
            final X500Name name) {
        ParamUtil.requireNonNull("name", name);
        ASN1ObjectIdentifier[] tmpTypes = name.getAttributeTypes();
        int n = tmpTypes.length;
        List<String> types = new ArrayList<>(n);
        for (ASN1ObjectIdentifier type : tmpTypes) {
            types.add(type.getId());
        }

        Collections.sort(types);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            String type = types.get(i);
            if (i > 0) {
                sb.append(",");
            }
            sb.append(type).append("=");
            RDN[] rdns = name.getRDNs(new ASN1ObjectIdentifier(type));

            List<String> values = new ArrayList<>(1);
            for (int j = 0; j < rdns.length; j++) {
                RDN rdn = rdns[j];
                if (rdn.isMultiValued()) {
                    AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
                    for (AttributeTypeAndValue atv : atvs) {
                        if (type.equals(atv.getType().getId())) {
                            String textValue =
                                    IETFUtils.valueToString(atv.getValue()).toLowerCase();
                            values.add(textValue);
                        }
                    }
                } else {
                    String textValue =
                            IETFUtils.valueToString(rdn.getFirst().getValue()).toLowerCase();
                    values.add(textValue);
                }
            } // end for(j)

            sb.append(values.get(0));

            final int n2 = values.size();
            if (n2 > 1) {
                for (int j = 1; j < n2; j++) {
                    sb.append(";").append(values.get(j));
                }
            }
        } // end for(i)

        return sb.toString();
    } // method canonicalizName

    public static byte[] extractSki(
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

    public static byte[] extractSki(
            final org.bouncycastle.asn1.x509.Certificate cert)
    throws CertificateEncodingException {
        ParamUtil.requireNonNull("cert", cert);
        Extension encodedSkiValue = cert.getTBSCertificate().getExtensions().getExtension(
                Extension.subjectKeyIdentifier);
        if (encodedSkiValue == null) {
            return null;
        }

        try {
            return ASN1OctetString.getInstance(encodedSkiValue.getParsedValue()).getOctets();
        } catch (IllegalArgumentException ex) {
            throw new CertificateEncodingException("invalid extension SubjectKeyIdentifier: "
                    + ex.getMessage());
        }
    }

    public static byte[] extractAki(
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
            throw new CertificateEncodingException("invalid extension AuthorityKeyIdentifier: "
                    + ex.getMessage());
        }
    }

    public static byte[] extractAki(
            final org.bouncycastle.asn1.x509.Certificate cert)
    throws CertificateEncodingException {
        ParamUtil.requireNonNull("cert", cert);
        try {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(
                    cert.getTBSCertificate().getExtensions());
            return (aki == null)
                    ? null
                    : aki.getKeyIdentifier();
        } catch (IllegalArgumentException ex) {
            throw new CertificateEncodingException("invalid extension AuthorityKeyIdentifier: "
                    + ex.getMessage());
        }
    }

    public static String rdnValueToString(
            final ASN1Encodable value) {
        ParamUtil.requireNonNull("value", value);
        if (value instanceof ASN1String && !(value instanceof DERUniversalString)) {
            return ((ASN1String) value).getString();
        } else {
            try {
                return "#" + bytesToString(
                        Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
            } catch (IOException ex) {
                throw new IllegalArgumentException("other value has no encoded form");
            }
        }
    }

    private static String bytesToString(
            final byte[] data) {
        char[] cs = new char[data.length];

        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (data[i] & 0xff);
        }

        return new String(cs);
    }

    public static org.bouncycastle.asn1.x509.KeyUsage createKeyUsage(
            final Set<KeyUsage> usages) {
        if (CollectionUtil.isEmpty(usages)) {
            return null;
        }

        int usage = 0;
        for (KeyUsage keyUsage : usages) {
            usage |= keyUsage.getBcUsage();
        }

        return new org.bouncycastle.asn1.x509.KeyUsage(usage);
    }

    public static ExtendedKeyUsage createExtendedUsage(
            final Collection<ASN1ObjectIdentifier> usages) {
        if (CollectionUtil.isEmpty(usages)) {
            return null;
        }

        List<ASN1ObjectIdentifier> l = new ArrayList<>(usages);
        List<ASN1ObjectIdentifier> sortedUsages = sortOidList(l);
        KeyPurposeId[] kps = new KeyPurposeId[sortedUsages.size()];

        int i = 0;
        for (ASN1ObjectIdentifier oid : sortedUsages) {
            kps[i++] = KeyPurposeId.getInstance(oid);
        }

        return new ExtendedKeyUsage(kps);
    }

    // sort the list and remove duplicated OID.
    public static List<ASN1ObjectIdentifier> sortOidList(
            List<ASN1ObjectIdentifier> oids) {
        ParamUtil.requireNonNull("oids", oids);
        List<String> l = new ArrayList<>(oids.size());
        for (ASN1ObjectIdentifier m : oids) {
            l.add(m.getId());
        }
        Collections.sort(l);

        List<ASN1ObjectIdentifier> sorted = new ArrayList<>(oids.size());
        for (String m : l) {
            for (ASN1ObjectIdentifier n : oids) {
                if (m.equals(n.getId()) && !sorted.contains(n)) {
                    sorted.add(n);
                }
            }
        }
        return sorted;
    }

    public static boolean hasKeyusage(
            final X509Certificate cert,
            final KeyUsage usage) {
        ParamUtil.requireNonNull("cert", cert);
        boolean[] keyusage = cert.getKeyUsage();
        if (keyusage != null && keyusage.length > usage.getBit()) {
            return keyusage[usage.getBit()];
        }
        return false;
    }

    public static byte[] getCoreExtValue(
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
            throw new CertificateEncodingException("invalid extension " + type.getId() + ": "
                    + ex.getMessage());
        }
    }

    /**
     * Cross certificate will not be considered
     */
    public static X509Certificate[] buildCertPath(
            final X509Certificate cert,
            final Set<? extends Certificate> certs) {
        ParamUtil.requireNonNull("cert", cert);
        List<X509Certificate> certChain = new LinkedList<>();
        certChain.add(cert);
        try {
            if (certs != null && !isSelfSigned(cert)) {
                while (true) {
                    X509Certificate caCert = getCaCertOf(certChain.get(certChain.size() - 1),
                            certs);
                    if (caCert == null) {
                        break;
                    }
                    certChain.add(caCert);
                    if (isSelfSigned(caCert)) {
                        // reaches root self-signed certificate
                        break;
                    }
                }
            }
        } catch (CertificateEncodingException ex) {
        }

        final int n = certChain.size();
        int len = n;
        if (n > 1) {
            for (int i = 1; i < n; i++) {
                int pathLen = certChain.get(i).getBasicConstraints();
                if (pathLen < 0 || pathLen < i) {
                    len = i;
                    break;
                }
            }
        } // end for

        if (len == n) {
            return certChain.toArray(new X509Certificate[0]);
        } else {
            X509Certificate[] ret = new X509Certificate[len];
            for (int i = 0; i < len; i++) {
                ret[i] = certChain.get(i);
            }
            return ret;
        }
    } // method buildCertPath

    private static X509Certificate getCaCertOf(
            final X509Certificate cert,
            final Set<? extends Certificate> caCerts)
    throws CertificateEncodingException {
        ParamUtil.requireNonNull("cert", cert);
        if (isSelfSigned(cert)) {
            return null;
        }

        for (Certificate caCert : caCerts) {
            if (!(caCert instanceof X509Certificate)) {
                continue;
            }

            X509Certificate x509CaCert = (X509Certificate) caCert;
            if (!issues(x509CaCert, cert)) {
                continue;
            }

            try {
                cert.verify(x509CaCert.getPublicKey());
                return x509CaCert;
            } catch (Exception ex) {
            }
        }

        return null;
    }

    public static boolean isSelfSigned(
            final X509Certificate cert)
    throws CertificateEncodingException {
        ParamUtil.requireNonNull("cert", cert);
        boolean equals = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (equals) {
            byte[] ski = extractSki(cert);
            byte[] aki = extractAki(cert);
            if (ski != null && aki != null) {
                equals = Arrays.equals(ski, aki);
            }
        }
        return equals;
    }

    public static boolean issues(
            final X509Certificate issuerCert,
            final X509Certificate cert)
    throws CertificateEncodingException {
        ParamUtil.requireNonNull("issuerCert", issuerCert);
        ParamUtil.requireNonNull("cert", cert);
        boolean isCA = issuerCert.getBasicConstraints() >= 0;
        if (!isCA) {
            return false;
        }

        boolean issues = issuerCert.getSubjectX500Principal().equals(
                cert.getIssuerX500Principal());
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

    public static SubjectPublicKeyInfo toRfc3279Style(
            final SubjectPublicKeyInfo publicKeyInfo)
    throws InvalidKeySpecException {
        ParamUtil.requireNonNull("publicKeyInfo", publicKeyInfo);
        ASN1ObjectIdentifier algOid = publicKeyInfo.getAlgorithm().getAlgorithm();
        ASN1Encodable keyParameters = publicKeyInfo.getAlgorithm().getParameters();

        if (PKCSObjectIdentifiers.rsaEncryption.equals(algOid)) {
            if (DERNull.INSTANCE.equals(keyParameters)) {
                return publicKeyInfo;
            } else {
                AlgorithmIdentifier keyAlgId = new AlgorithmIdentifier(algOid, DERNull.INSTANCE);
                return new SubjectPublicKeyInfo(keyAlgId,
                        publicKeyInfo.getPublicKeyData().getBytes());
            }
        } else if (X9ObjectIdentifiers.id_dsa.equals(algOid)) {
            if (keyParameters == null) {
                return publicKeyInfo;
            } else if (DERNull.INSTANCE.equals(keyParameters)) {
                AlgorithmIdentifier keyAlgId = new AlgorithmIdentifier(algOid);
                return new SubjectPublicKeyInfo(keyAlgId,
                        publicKeyInfo.getPublicKeyData().getBytes());
            } else {
                try {
                    DSAParameter.getInstance(keyParameters);
                } catch (IllegalArgumentException ex) {
                    throw new InvalidKeySpecException("keyParameters is not null and Dss-Parms");
                }
                return publicKeyInfo;
            }
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(algOid)) {
            if (keyParameters == null) {
                throw new InvalidKeySpecException("keyParameters is not an OBJECT IDENTIFIER");
            }
            try {
                ASN1ObjectIdentifier.getInstance(keyParameters);
            } catch (IllegalArgumentException ex) {
                throw new InvalidKeySpecException("keyParameters is not an OBJECT IDENTIFIER");
            }
            return publicKeyInfo;
        } else {
            return publicKeyInfo;
        }
    }

    public static String cutText(
            final String text,
            final int maxLen) {
        ParamUtil.requireNonNull("text", text);
        if (text.length() <= maxLen) {
            return text;
        }
        StringBuilder sb = new StringBuilder(maxLen);
        sb.append(text.substring(0, maxLen - 13));
        sb.append("...skipped...");
        return sb.toString();
    }

    public static String cutX500Name(
            final X500Name name,
            final int maxLen) {
        String text = getRfc4519Name(name);
        return cutText(text, maxLen);
    }

    public static String cutX500Name(
            final X500Principal name,
            final int maxLen) {
        String text = getRfc4519Name(name);
        return cutText(text, maxLen);
    }

    public static Extension createExtensionSubjectAltName(
            final List<String> taggedValues,
            final boolean critical)
    throws BadInputException {
        GeneralNames names = createGeneralNames(taggedValues);
        if (names == null) {
            return null;
        }

        try {
            return new Extension(Extension.subjectAlternativeName, critical, names.getEncoded());
        } catch (IOException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public static Extension createExtensionSubjectInfoAccess(
            final List<String> accessMethodAndLocations,
            final boolean critical)
    throws BadInputException {
        if (CollectionUtil.isEmpty(accessMethodAndLocations)) {
            return null;
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (String accessMethodAndLocation : accessMethodAndLocations) {
            vector.add(createAccessDescription(accessMethodAndLocation));
        }
        ASN1Sequence seq = new DERSequence(vector);
        try {
            return new Extension(Extension.subjectInfoAccess, critical, seq.getEncoded());
        } catch (IOException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public static AccessDescription createAccessDescription(
            final String accessMethodAndLocation)
    throws BadInputException {
        ParamUtil.requireNonNull("accessMethodAndLocation", accessMethodAndLocation);
        ConfPairs pairs;
        try {
            pairs = new ConfPairs(accessMethodAndLocation);
        } catch (IllegalArgumentException ex) {
            throw new BadInputException("invalid accessMethodAndLocation "
                    + accessMethodAndLocation);
        }

        Set<String> oids = pairs.getNames();
        if (oids == null || oids.size() != 1) {
            throw new BadInputException("invalid accessMethodAndLocation "
                    + accessMethodAndLocation);
        }

        String accessMethodS = oids.iterator().next();
        String taggedValue = pairs.getValue(accessMethodS);
        ASN1ObjectIdentifier accessMethod = new ASN1ObjectIdentifier(accessMethodS);

        GeneralName location = createGeneralName(taggedValue);
        return new AccessDescription(accessMethod, location);
    }

    public static GeneralNames createGeneralNames(
            final List<String> taggedValues)
    throws BadInputException {
        if (CollectionUtil.isEmpty(taggedValues)) {
            return null;
        }

        int n = taggedValues.size();
        GeneralName[] names = new GeneralName[n];
        for (int i = 0; i < n; i++) {
            names[i] = createGeneralName(taggedValues.get(i));
        }
        return new GeneralNames(names);
    }

    /**
    *
    * @param taggedValue [tag]value, and the value for tags otherName and ediPartyName is
    *     type=value.
    * @param modes
    * @return
    * @throws BadInputException
    */
    public static GeneralName createGeneralName(
            final String taggedValue)
    throws BadInputException {
        ParamUtil.requireNonBlank("taggedValue", taggedValue);

        int tag = -1;
        String value = null;
        if (taggedValue.charAt(0) == '[') {
            int idx = taggedValue.indexOf(']', 1);
            if (idx > 1 && idx < taggedValue.length() - 1) {
                String tagS = taggedValue.substring(1, idx);
                try {
                    tag = Integer.parseInt(tagS);
                    value = taggedValue.substring(idx + 1);
                } catch (NumberFormatException ex) {
                }
            }
        }

        if (tag == -1) {
            throw new BadInputException("invalid taggedValue " + taggedValue);
        }

        switch (tag) {
        case GeneralName.otherName:
            int idxSep = value.indexOf("=");
            if (idxSep == -1 || idxSep == 0 || idxSep == value.length() - 1) {
                throw new BadInputException("invalid otherName " + value);
            }
            String otherTypeOid = value.substring(0, idxSep);
            ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(otherTypeOid);
            String otherValue = value.substring(idxSep + 1);
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(type);
            vector.add(new DERTaggedObject(true, 0, new DERUTF8String(otherValue)));
            DERSequence seq = new DERSequence(vector);
            return new GeneralName(GeneralName.otherName, seq);
        case GeneralName.rfc822Name:
            return new GeneralName(tag, value);
        case GeneralName.dNSName:
            return new GeneralName(tag, value);
        case GeneralName.directoryName:
            X500Name x500Name = X509Util.reverse(new X500Name(value));
            return new GeneralName(GeneralName.directoryName, x500Name);
        case GeneralName.ediPartyName:
            idxSep = value.indexOf("=");
            if (idxSep == -1 || idxSep == value.length() - 1) {
                throw new BadInputException("invalid ediPartyName " + value);
            }
            String nameAssigner = (idxSep == 0)
                    ? null
                    : value.substring(0, idxSep);
            String partyName = value.substring(idxSep + 1);
            vector = new ASN1EncodableVector();
            if (nameAssigner != null) {
                vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
            }
            vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
            seq = new DERSequence(vector);
            return new GeneralName(GeneralName.ediPartyName, seq);
        case GeneralName.uniformResourceIdentifier:
            return new GeneralName(tag, value);
        case GeneralName.iPAddress:
            return new GeneralName(tag, value);
        case GeneralName.registeredID:
            return new GeneralName(tag, value);
        default:
            throw new RuntimeException("unsupported tag " + tag);
        } // end switch (tag)
    } // method createGeneralName

}
