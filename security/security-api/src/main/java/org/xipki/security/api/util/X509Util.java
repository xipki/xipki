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

package org.xipki.security.api.util;

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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.security.api.KeyUsage;
import org.xipki.security.api.FpIdCalculator;
import org.xipki.security.api.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class X509Util {
    private X509Util() {
    }

    public static String getCommonName(
            final X500Principal name) {
        return getCommonName(X500Name.getInstance(name.getEncoded()));
    }

    public static String getCommonName(
            final X500Name name) {
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
        RDN[] orig = name.getRDNs();
        int n = orig.length;
        RDN[] _new = new RDN[n];
        for (int i = 0; i < n; i++) {
            _new[i] = orig[n - 1 - i];
        }
        return new X500Name(_new);
    }

    public static X500Name sortX509Name(
            final X500Name name) {
        return sortX500Name(name, false);
    }

    public static X500Name backwardSortX509Name(
            final X500Name name) {
        return sortX500Name(name, true);
    }

    private static X500Name sortX500Name(
            final X500Name name,
            final boolean backwards) {
        RDN[] requstedRDNs = name.getRDNs();

        List<RDN> rdns = new LinkedList<>();

        List<ASN1ObjectIdentifier> sortedDNs = backwards
                ? ObjectIdentifiers.getBackwardDNs()
                : ObjectIdentifiers.getForwardDNs();
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

    private static CertificateFactory certFact;
    private static Object certFactLock = new Object();

    public static X509Certificate parseCert(
            final String fileName)
    throws IOException, CertificateException {
        return parseCert(new File(IoUtil.expandFilepath(fileName)));
    }

    public static X509Certificate parseCert(
            final File file)
    throws IOException, CertificateException {
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
        return parseCert(new ByteArrayInputStream(certBytes));
    }

    public static X509Certificate parseBase64EncodedCert(
            final String base64EncodedCert)
    throws IOException, CertificateException {
        return parseCert(Base64.decode(base64EncodedCert));
    }

    public static X509Certificate parseCert(
            final InputStream certStream)
    throws IOException, CertificateException {
        synchronized (certFactLock) {
            if (certFact == null) {
                try {
                    certFact = CertificateFactory.getInstance("X.509", "BC");
                } catch (NoSuchProviderException e) {
                    throw new IOException("NoSuchProviderException: " + e.getMessage());
                }
            }
        }

        return (X509Certificate) certFact.generateCertificate(certStream);
    }

    public static X509CRL parseCRL(
            final String f)
    throws IOException, CertificateException, CRLException {
        return parseCRL(new FileInputStream(IoUtil.expandFilepath(f)));
    }

    public static X509CRL parseCRL(
            final InputStream crlStream)
    throws IOException, CertificateException, CRLException {
        try {
            if (certFact == null) {
                certFact = CertificateFactory.getInstance("X.509", "BC");
            }
            return (X509CRL) certFact.generateCRL(crlStream);
        } catch (NoSuchProviderException e) {
            throw new IOException("NoSuchProviderException: " + e.getMessage());
        }
    }

    public static String getRFC4519Name(
            final X500Principal name) {
        return getRFC4519Name(X500Name.getInstance(name.getEncoded()));
    }

    public static String getRFC4519Name(
            final X500Name name) {
        return RFC4519Style.INSTANCE.toString(name);
    }

    /**
     * First canonicalized the name, and then compute the SHA-1 finger-print over the
     * canonicalized subject string.
     */
    public static long fp_canonicalized_name(
            final X500Principal prin) {
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return fp_canonicalized_name(x500Name);
    }

    public static long fp_canonicalized_name(
            final X500Name name) {
        String canonicalizedName = canonicalizName(name);
        byte[] encoded;
        try {
            encoded = canonicalizedName.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            encoded = canonicalizedName.getBytes();
        }
        return FpIdCalculator.hash(encoded);
    }

    public static String canonicalizName(
            final X500Principal prin) {
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return canonicalizName(x500Name);
    }

    public static String canonicalizName(
            final X500Name name) {
        ASN1ObjectIdentifier[] _types = name.getAttributeTypes();
        int n = _types.length;
        List<String> types = new ArrayList<>(n);
        for (ASN1ObjectIdentifier type : _types) {
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
            }

            sb.append(values.get(0));

            final int n2 = values.size();
            if (n2 > 1) {
                for (int j = 1; j < n2; j++) {
                    sb.append(";").append(values.get(j));
                }
            }
        }

        return sb.toString();
    }

    public static byte[] extractSKI(
            final X509Certificate cert)
    throws CertificateEncodingException {
        byte[] extValue = getCoreExtValue(cert, Extension.subjectKeyIdentifier);
        if (extValue == null) {
            return null;
        }

        try {
            return ASN1OctetString.getInstance(extValue).getOctets();
        } catch (IllegalArgumentException e) {
            throw new CertificateEncodingException(e.getMessage());
        }
    }

    public static byte[] extractSKI(
            final org.bouncycastle.asn1.x509.Certificate cert)
    throws CertificateEncodingException {
        Extension encodedSkiValue = cert.getTBSCertificate().getExtensions().getExtension(
                Extension.subjectKeyIdentifier);
        if (encodedSkiValue == null) {
            return null;
        }

        try {
            return ASN1OctetString.getInstance(encodedSkiValue.getParsedValue()).getOctets();
        } catch (IllegalArgumentException e) {
            throw new CertificateEncodingException("invalid extension SubjectKeyIdentifier: "
                    + e.getMessage());
        }
    }

    public static byte[] extractAKI(
            final X509Certificate cert)
    throws CertificateEncodingException {
        byte[] extValue = getCoreExtValue(cert, Extension.authorityKeyIdentifier);
        if (extValue == null) {
            return null;
        }

        try {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extValue);
            return aki.getKeyIdentifier();
        } catch (IllegalArgumentException e) {
            throw new CertificateEncodingException("invalid extension AuthorityKeyIdentifier: "
                    + e.getMessage());
        }
    }

    public static List<String> extractOCSPUrls(
            final X509Certificate cert)
    throws CertificateEncodingException {
        byte[] extValue = getCoreExtValue(cert, Extension.authorityInfoAccess);
        if (extValue == null) {
            return Collections.emptyList();
        }

        AuthorityInformationAccess iAIA = AuthorityInformationAccess.getInstance(extValue);

        AccessDescription[] iAccessDescriptions = iAIA.getAccessDescriptions();
        List<AccessDescription> iOCSPAccessDescriptions = new LinkedList<>();
        for (AccessDescription iAccessDescription : iAccessDescriptions) {
            if (iAccessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                iOCSPAccessDescriptions.add(iAccessDescription);
            }
        }

        int n = iOCSPAccessDescriptions.size();
        List<String> OCSPUris = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            GeneralName iAccessLocation = iOCSPAccessDescriptions.get(i).getAccessLocation();
            if (iAccessLocation.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String iOCSPUri = ((ASN1String) iAccessLocation.getName()).getString();
                OCSPUris.add(iOCSPUri);
            }
        }

        return OCSPUris;
    }

    public static byte[] extractAKI(
            final org.bouncycastle.asn1.x509.Certificate cert)
    throws CertificateEncodingException {
        try {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(
                    cert.getTBSCertificate().getExtensions());
            return (aki == null)
                    ? null
                    : aki.getKeyIdentifier();
        } catch (IllegalArgumentException e) {
            throw new CertificateEncodingException("invalid extension AuthorityKeyIdentifier: "
                    + e.getMessage());
        }
    }

    public static String rdnValueToString(
            final ASN1Encodable value) {
        if (value instanceof ASN1String && !(value instanceof DERUniversalString)) {
            return ((ASN1String) value).getString();
        } else {
            try {
                return "#" + bytesToString(
                        Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
            }
            catch (IOException e) {
                throw new IllegalArgumentException("other value has no encoded form");
            }
        }
    }

    private static String bytesToString(
            final byte[] data) {
        char[]  cs = new char[data.length];

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
            final Set<ASN1ObjectIdentifier> usages) {
        if (CollectionUtil.isEmpty(usages)) {
            return null;
        }

        KeyPurposeId[] kps = new KeyPurposeId[usages.size()];

        int i = 0;
        for (ASN1ObjectIdentifier oid : usages) {
            kps[i++] = KeyPurposeId.getInstance(oid);
        }

        return new ExtendedKeyUsage(kps);
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
        byte[] fullExtValue = cert.getExtensionValue(type.getId());
        if (fullExtValue == null) {
            return null;
        }
        try {
            return ASN1OctetString.getInstance(fullExtValue).getOctets();
        } catch (IllegalArgumentException e) {
            throw new CertificateEncodingException("invalid extension " + type.getId() + ": "
                    + e.getMessage());
        }
    }

    /**
     * Cross certificate will not be considered
     */
    public static X509Certificate[] buildCertPath(
            final X509Certificate cert,
            final Set<? extends Certificate> certs) {
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
        } catch (CertificateEncodingException e) {
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
        }

        if (len == n) {
            return certChain.toArray(new X509Certificate[0]);
        } else {
            X509Certificate[] ret = new X509Certificate[len];
            for (int i = 0; i < len; i++) {
                ret[i] = certChain.get(i);
            }
            return ret;
        }
    }

    public static X509Certificate[] buildCertPath(
            final X509Certificate cert,
            final Certificate[] certs) {
        Set<Certificate> setOfCerts = new HashSet<>();
        for (Certificate m : certs) {
            setOfCerts.add(m);
        }

        return buildCertPath(cert, setOfCerts);
    }

    public static X509Certificate getCaCertOf(
            final X509Certificate cert,
            final Set<? extends Certificate> caCerts)
    throws CertificateEncodingException {
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
            } catch (Exception e) {
            }
        }

        return null;
    }

    public static boolean isSelfSigned(
            final X509Certificate cert)
    throws CertificateEncodingException {
        boolean equals = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (equals) {
            byte[] ski = X509Util.extractSKI(cert);
            byte[] aki = X509Util.extractAKI(cert);
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
        boolean isCA = issuerCert.getBasicConstraints() >= 0;
        if (!isCA) {
            return false;
        }

        boolean issues = issuerCert.getSubjectX500Principal().equals(
                cert.getIssuerX500Principal());
        if (issues) {
            byte[] ski = X509Util.extractSKI(issuerCert);
            byte[] aki = X509Util.extractAKI(cert);
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
        // TODO: add support of other algorithms
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
        } else {
            return publicKeyInfo;
        }
    }

    public static Extensions getExtensions(
            final CertificationRequestInfo p10Req) {
        ASN1Set attrs = p10Req.getAttributes();
        for (int i = 0; i < attrs.size(); i++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
                return Extensions.getInstance(attr.getAttributeValues()[0]);
            }
        }
        return null;
    }

    public static String getChallengePassword(
            final CertificationRequestInfo p10Req) {
        ASN1Set attrs = p10Req.getAttributes();
        for (int i = 0; i < attrs.size(); i++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (PKCSObjectIdentifiers.pkcs_9_at_challengePassword.equals(attr.getAttrType())) {
                ASN1String str = (ASN1String) attr.getAttributeValues()[0];
                return str.getString();
            }
        }
        return null;
    }

    public static String cutText(String text, int maxLen) {
        if (text.length() <= maxLen) {
            return text;
        }
        StringBuilder sb = new StringBuilder(maxLen);
        sb.append(text.substring(0, maxLen - 13));
        sb.append("...skipped...");
        return sb.toString();
    }

    public static String cutX500Name(X500Name name, int maxLen) {
        String text = getRFC4519Name(name);
        return cutText(text, maxLen);
    }

    public static String cutX500Name(X500Principal name, int maxLen) {
        String text = getRFC4519Name(name);
        return cutText(text, maxLen);
    }

}
