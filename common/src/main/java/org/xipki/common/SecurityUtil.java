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

package org.xipki.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * @author Lijun Liao
 */

public class SecurityUtil
{
    public static final Map<Integer, String> statusTextMap = new HashMap<>();
    public static final String[] failureInfoTexts = new String[]
    {
        "incorrectData", "wrongAuthority", "badDataFormat", "badCertId", // 0 - 3
        "badTime", "badRequest", "badMessageCheck", "badAlg", // 4 - 7
        "unacceptedPolicy", "timeNotAvailable", "badRecipientNonce", "wrongIntegrity", // 8 - 11
        "certConfirmed", "certRevoked", "badPOP", "missingTimeStamp", // 12 - 15
        "notAuthorized", "unsupportedVersion", "transactionIdInUse", "signerNotTrusted", // 16 - 19
        "badCertTemplate", "badSenderNonce", "addInfoNotAvailable", "unacceptedExtension", // 20 - 23
        "-", "-", "-", "-", // 24 -27
        "-", "duplicateCertReq", "systemFailure", "systemUnavail"}; // 28 - 31

    static
    {
        statusTextMap.put(-2, "xipki_noAnswer");
        statusTextMap.put(-1, "xipki_responseError");
        statusTextMap.put(PKIStatus.GRANTED, "accepted");
        statusTextMap.put(PKIStatus.GRANTED_WITH_MODS, "grantedWithMods");
        statusTextMap.put(PKIStatus.REJECTION, "rejection");
        statusTextMap.put(PKIStatus.WAITING, "waiting");
        statusTextMap.put(PKIStatus.REVOCATION_WARNING, "revocationWarning");
        statusTextMap.put(PKIStatus.REVOCATION_NOTIFICATION, "revocationNotification");
        statusTextMap.put(PKIStatus.KEY_UPDATE_WARNING, "keyUpdateWarning");
    }

    public static String getCommonName(X500Name name)
    {
        RDN[] rdns = name.getRDNs(ObjectIdentifiers.DN_CN);
        if(rdns != null && rdns.length > 0)
        {
            return rdnValueToString(rdns[0].getFirst().getValue());
        }
        return null;
    }

    public static X500Name reverse(X500Name name)
    {
        RDN[] orig = name.getRDNs();
        int n = orig.length;
        RDN[] _new = new RDN[n];
        for(int i = 0; i < n; i++)
        {
            _new[i] = orig[n - 1 - i];
        }
        return new X500Name(_new);
    }

    public static X500Name sortX509Name(X500Name name)
    {
        return sortX500Name(name, false);
    }

    public static X500Name backwardSortX509Name(X500Name name)
    {
        return sortX500Name(name, true);
    }

    private static X500Name sortX500Name(X500Name name, boolean backwards)
    {
        RDN[] requstedRDNs = name.getRDNs();

        List<RDN> rdns = new LinkedList<>();

        List<ASN1ObjectIdentifier> sortedDNs = backwards ?
                ObjectIdentifiers.getBackwardDNs() : ObjectIdentifiers.getForwardDNs();
        int size = sortedDNs.size();
        for(int i = 0; i < size; i++)
        {
            ASN1ObjectIdentifier type = sortedDNs.get(i);
            RDN[] thisRDNs = getRDNs(requstedRDNs, type);
            int n = thisRDNs == null ? 0 : thisRDNs.length;
            if(n == 0)
            {
                continue;
            }

            for(RDN thisRDN : thisRDNs)
            {
                rdns.add(thisRDN);
            }
        }

        return new X500Name(rdns.toArray(new RDN[0]));
    }

    private static RDN[] getRDNs(RDN[] rdns, ASN1ObjectIdentifier type)
    {
        List<RDN> ret = new ArrayList<>(1);
        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            if(rdn.getFirst().getType().equals(type))
            {
                ret.add(rdn);
            }
        }

        if(ret.isEmpty())
        {
            return null;
        }
        else
        {
            return ret.toArray(new RDN[0]);
        }
    }

    private static CertificateFactory certFact;
    private static Object certFactLock = new Object();

    public static X509Certificate parseCert(String fileName)
    throws IOException, CertificateException
    {
        return parseCert(new File(IoUtil.expandFilepath(fileName)));
    }

    public static X509Certificate parseCert(File file)
    throws IOException, CertificateException
    {
        FileInputStream in = new FileInputStream(IoUtil.expandFilepath(file));
        try
        {
            return parseCert(in);
        }finally
        {
            in.close();
        }
    }

    public static X509Certificate parseCert(byte[] certBytes)
    throws IOException, CertificateException
    {
        return parseCert(new ByteArrayInputStream(certBytes));
    }

    public static X509Certificate parseBase64EncodedCert(String base64EncodedCert)
    throws IOException, CertificateException
    {
        return parseCert(Base64.decode(base64EncodedCert));
    }

    public static X509Certificate parseCert(InputStream certStream)
    throws IOException, CertificateException
    {
        synchronized (certFactLock)
        {
            if (certFact == null)
            {
                try
                {
                    certFact = CertificateFactory.getInstance("X.509", "BC");
                } catch (NoSuchProviderException e)
                {
                    throw new IOException("NoSuchProviderException: " + e.getMessage());
                }
            }
        }

        return (X509Certificate) certFact.generateCertificate(certStream);
    }

    public static X509CRL parseCRL(String f)
    throws IOException, CertificateException, CRLException
    {
        return parseCRL(new FileInputStream(IoUtil.expandFilepath(f)));
    }

    public static X509CRL parseCRL(InputStream crlStream)
    throws IOException, CertificateException, CRLException
    {
        try
        {
            if(certFact == null)
            {
                certFact = CertificateFactory.getInstance("X.509", "BC");
            }
            return (X509CRL) certFact.generateCRL(crlStream);
        } catch (NoSuchProviderException e)
        {
            throw new IOException("NoSuchProviderException: " + e.getMessage());
        }
    }

    public static String getRFC4519Name(X500Principal name)
    {
        return getRFC4519Name(X500Name.getInstance(name.getEncoded()));
    }

    public static String getRFC4519Name(X500Name name)
    {
        return RFC4519Style.INSTANCE.toString(name);
    }

    /**
     * First canonicalized the name, and then compute the SHA-1 finger-print over the
     * canonicalized subject string.
     */
    public static String sha1sum_canonicalized_name(X500Principal prin)
    {
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return sha1sum_canonicalized_name(x500Name);
    }

    public static String sha1sum_canonicalized_name(X500Name name)
    {
        String canonicalizedName = canonicalizName(name);
        byte[] encoded;
        try
        {
            encoded = canonicalizedName.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e)
        {
            encoded = canonicalizedName.getBytes();
        }
        return sha1sum(encoded);
    }

    public static String canonicalizName(X500Principal prin)
    {
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return canonicalizName(x500Name);
    }

    public static String canonicalizName(X500Name name)
    {
        ASN1ObjectIdentifier[] _types = name.getAttributeTypes();
        int n = _types.length;
        List<String> types = new ArrayList<>(n);
        for(ASN1ObjectIdentifier type : _types)
        {
            types.add(type.getId());
        }

        Collections.sort(types);

        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < n; i++)
        {
            String type = types.get(i);
            if(i > 0)
            {
                sb.append(",");
            }
            sb.append(type).append("=");
            RDN[] rdns = name.getRDNs(new ASN1ObjectIdentifier(type));

            for(int j = 0; j < rdns.length; j++)
            {
                if(j > 0)
                {
                    sb.append(";");
                }
                RDN rdn = rdns[j];
                String textValue = IETFUtils.valueToString(rdn.getFirst().getValue()).toLowerCase();
                sb.append(textValue);
            }
        }

        return sb.toString();
    }

    public static String sha1sum(byte[] data)
    {
        return HashCalculator.hexHash(HashAlgoType.SHA1, data);
    }

    public static byte[] extractMinimalKeyStore(String keystoreType, byte[] keystoreBytes,
            String keyname, char[] password)
    throws Exception
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
        ks.load(new ByteArrayInputStream(keystoreBytes), password);

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
                throw new KeyStoreException("unknown key named " + keyname);
            }
        }

        Enumeration<String> aliases = ks.aliases();
        int numAliases = 0;
        while(aliases.hasMoreElements())
        {
            aliases.nextElement();
            numAliases++;
        }

        Certificate[] certs = ks.getCertificateChain(keyname);
        if(numAliases == 1)
        {
            return keystoreBytes;
        }

        PrivateKey key = (PrivateKey) ks.getKey(keyname, password);
        ks = null;

        if("JKS".equalsIgnoreCase(keystoreType))
        {
            ks = KeyStore.getInstance(keystoreType);
        }
        else
        {
            ks = KeyStore.getInstance(keystoreType, "BC");
        }
        ks.load(null, password);
        ks.setKeyEntry(keyname, key, password, certs);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ks.store(bout, password);
        byte[] bytes = bout.toByteArray();
        bout.close();
        return bytes;
    }

    public static X509Certificate[] buildCertPath(X509Certificate cert, Set<? extends Certificate> certs)
    {
        List<X509Certificate> certChain = new LinkedList<>();
        certChain.add(cert);
        if(certs != null && isSelfSigned(cert) == false)
        {
            while(true)
            {
                X509Certificate caCert = getCaCertOf(certChain.get(certChain.size() - 1), certs);
                if(caCert == null)
                {
                    break;
                }
                certChain.add(caCert);
                if(isSelfSigned(caCert))
                {
                    // reaches root self-signed certificate
                    break;
                }
            }
        }

        return certChain.toArray(new X509Certificate[0]);
    }

    public static X509Certificate[] buildCertPath(X509Certificate cert, Certificate[] certs)
    {
        Set<Certificate> setOfCerts = new HashSet<>();
        for(Certificate entry : certs)
        {
            setOfCerts.add(entry);
        }

        return buildCertPath(cert, setOfCerts);
    }

    private static X509Certificate getCaCertOf(X509Certificate cert,
            Set<? extends Certificate> caCerts)
    {
        if(isSelfSigned(cert))
        {
            return null;
        }

        X500Principal issuer = cert.getIssuerX500Principal();

        for(Certificate caCert : caCerts)
        {
            if(caCert instanceof X509Certificate == false)
            {
                continue;
            }

            X509Certificate x509Cert = (X509Certificate) caCert;
            if(issuer.equals(x509Cert.getSubjectX500Principal()) == false)
            {
                continue;
            }

            boolean isCACert = x509Cert.getBasicConstraints() >= 0;
            if(isCACert == false)
            {
                continue;
            }

            try
            {
                cert.verify(x509Cert.getPublicKey());
                return x509Cert;
            } catch (Exception e)
            {
            }
        }

        return null;
    }

    public static String formatPKIStatusInfo(org.bouncycastle.asn1.cmp.PKIStatusInfo pkiStatusInfo)
    {
        int status = pkiStatusInfo.getStatus().intValue();
        int failureInfo = pkiStatusInfo.getFailInfo().intValue();
        PKIFreeText text = pkiStatusInfo.getStatusString();
        String statusMessage = text == null ? null : text.getStringAt(0).getString();

        return SecurityUtil.formatPKIStatusInfo(status, failureInfo, statusMessage);
    }

    public static String formatPKIStatusInfo(int status, int failureInfo, String statusMessage)
    {
        StringBuilder sb = new StringBuilder("PKIStatusInfo {");
        sb.append("status = ");
        sb.append(status);
        sb.append(" (").append(statusTextMap.get(status)).append("), ");
        sb.append("failureInfo = ");
        sb.append(failureInfo).append(" (").append(getFailureInfoText(failureInfo)).append("), ");
        sb.append("statusMessage = ").append(statusMessage);
        sb.append("}");
        return sb.toString();
    }

    public static String getFailureInfoText(int failureInfo)
    {
        BigInteger b = BigInteger.valueOf(failureInfo);
        final int n = Math.min(b.bitLength(), failureInfoTexts.length);

        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < n; i++)
        {
            if(b.testBit(i))
            {
                sb.append(", ").append(failureInfoTexts[i]);
            }
        }

        return sb.length() < 3 ? "" : sb.substring(2);
    }

    public static boolean isSelfSigned(X509Certificate cert)
    {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }

    public static byte[] leftmost(byte[] bytes, int bitCount)
    {
        int byteLenKey = (bitCount + 7)/8;

        if (bitCount >= (bytes.length << 3))
        {
            return bytes;
        }

        byte[] truncatedBytes = new byte[byteLenKey];
        System.arraycopy(bytes, 0, truncatedBytes, 0, byteLenKey);

        if (bitCount%8 > 0) // shift the bits to the right
        {
            int shiftBits = 8-(bitCount%8);

            for(int i = byteLenKey - 1; i > 0; i--)
            {
                truncatedBytes[i] = (byte) (
                        (byte2int(truncatedBytes[i]) >>> shiftBits) |
                        ((byte2int(truncatedBytes[i- 1]) << (8 - shiftBits)) & 0xFF));
            }
            truncatedBytes[0] = (byte)(byte2int(truncatedBytes[0]) >>> shiftBits);
        }

        return truncatedBytes;
    }

    private static int byte2int(byte b)
    {
        return b >= 0 ? b : 256 + b;
    }

    public static SubjectPublicKeyInfo toRfc3279Style(SubjectPublicKeyInfo publicKeyInfo)
    throws InvalidKeySpecException
    {
        // TODO: add support of other algorithms
        ASN1ObjectIdentifier algOid = publicKeyInfo.getAlgorithm().getAlgorithm();
        ASN1Encodable keyParameters = publicKeyInfo.getAlgorithm().getParameters();

        if(PKCSObjectIdentifiers.rsaEncryption.equals(algOid))
        {
            if(DERNull.INSTANCE.equals(keyParameters))
            {
                return publicKeyInfo;
            }
            else
            {
                AlgorithmIdentifier keyAlgId = new AlgorithmIdentifier(algOid, DERNull.INSTANCE);
                return new SubjectPublicKeyInfo(keyAlgId, publicKeyInfo.getPublicKeyData().getBytes());
            }
        } else
        {
            return publicKeyInfo;
        }
    }

    public static String getCurveName(ASN1ObjectIdentifier curveId)
    {
        String curveName = X962NamedCurves.getName(curveId);

        if (curveName == null)
        {
            curveName = SECNamedCurves.getName(curveId);
        }

        if (curveName == null)
        {
            curveName = TeleTrusTNamedCurves.getName(curveId);
        }

        if (curveName == null)
        {
            curveName = NISTNamedCurves.getName(curveId);
        }

        return curveName;
    }

    public static byte[] extractSKI(X509Certificate cert)
    throws CertificateEncodingException
    {
        byte[] encodedExtValue = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if(encodedExtValue == null)
        {
            return null;
        }

        try
        {
            ASN1OctetString ski = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedExtValue);
            return ski.getOctets();
        } catch (IOException e)
        {
            throw new CertificateEncodingException("Invalid extension SubjectKeyIdentifier: " + e.getMessage());
        }
    }

    public static byte[] extractSKI(org.bouncycastle.asn1.x509.Certificate cert)
    throws CertificateEncodingException
    {
        Extension encodedSkiValue = cert.getTBSCertificate().getExtensions().getExtension(Extension.subjectKeyIdentifier);
        if(encodedSkiValue == null)
        {
            return null;
        }

        try
        {
            return ASN1OctetString.getInstance(encodedSkiValue.getParsedValue()).getOctets();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException("Invalid extension SubjectKeyIdentifier: " + e.getMessage());
        }
    }

    public static byte[] extractAKI(X509Certificate cert)
    throws CertificateEncodingException
    {
        byte[] encodedExtValue = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if(encodedExtValue == null)
        {
            return null;
        }

        try
        {
            ASN1OctetString v = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedExtValue);
            byte[] extValue = v.getOctets();
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extValue);
            return aki.getKeyIdentifier();
        } catch (IOException e)
        {
            throw new CertificateEncodingException("Invalid extension AuthorityKeyIdentifier: " + e.getMessage());
        }
    }

    public static byte[] extractAKI(org.bouncycastle.asn1.x509.Certificate cert)
    throws CertificateEncodingException
    {
        try
        {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(
                    cert.getTBSCertificate().getExtensions());
            return aki == null ? null : aki.getKeyIdentifier();
        } catch (IllegalArgumentException e)
        {
            throw new CertificateEncodingException("Invalid extension AuthorityKeyIdentifier: " + e.getMessage());
        }
    }

    public static String rdnValueToString(ASN1Encodable value)
    {
        if (value instanceof ASN1String && !(value instanceof DERUniversalString))
        {
            return ((ASN1String)value).getString();
        }
        else
        {
            try
            {
                return "#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Other value has no encoded form");
            }
        }
    }

    private static String bytesToString(byte[] data)
    {
        char[]  cs = new char[data.length];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)(data[i] & 0xff);
        }

        return new String(cs);
    }
}
