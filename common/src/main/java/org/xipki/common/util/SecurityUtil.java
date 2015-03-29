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

package org.xipki.common.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.HashAlgoType;
import org.xipki.common.HashCalculator;
import org.xipki.common.InvalidOIDorNameException;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;

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

    public static String sha1sum(
            final byte[] data)
    {
        return HashCalculator.hexHash(HashAlgoType.SHA1, data);
    }

    public static byte[] extractMinimalKeyStore(
            final String keystoreType,
            final byte[] keystoreBytes,
            String keyname,
            final char[] password)
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

    public static String formatPKIStatusInfo(
            final org.bouncycastle.asn1.cmp.PKIStatusInfo pkiStatusInfo)
    {
        int status = pkiStatusInfo.getStatus().intValue();
        int failureInfo = pkiStatusInfo.getFailInfo().intValue();
        PKIFreeText text = pkiStatusInfo.getStatusString();
        String statusMessage = text == null ? null : text.getStringAt(0).getString();

        return SecurityUtil.formatPKIStatusInfo(status, failureInfo, statusMessage);
    }

    public static String formatPKIStatusInfo(
            final int status,
            final int failureInfo,
            final String statusMessage)
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

    public static String getFailureInfoText(
            final int failureInfo)
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

    public static byte[] leftmost(
            final byte[] bytes,
            final int bitCount)
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

    private static int byte2int(
            final byte b)
    {
        return b >= 0 ? b : 256 + b;
    }

    public static SubjectPublicKeyInfo toRfc3279Style(
            final SubjectPublicKeyInfo publicKeyInfo)
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

    public static String getCurveName(
            final ASN1ObjectIdentifier curveId)
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

    public static List<ASN1ObjectIdentifier> textToASN1ObjectIdentifers(
            final List<String> oidTexts)
    throws InvalidOIDorNameException
    {
        if(oidTexts == null)
        {
            return null;
        }

        List<ASN1ObjectIdentifier> ret = new ArrayList<>(oidTexts.size());
        for(String oidText : oidTexts)
        {
            if(oidText.isEmpty())
            {
                continue;
            }

            ASN1ObjectIdentifier oid = toOID(oidText);
            if(ret.contains(oid) == false)
            {
                ret.add(oid);
            }
        }
        return ret;
    }

    private static ASN1ObjectIdentifier toOID(
            final String s)
    throws InvalidOIDorNameException
    {
        final int n = s.length();
        boolean isName = false;
        for(int i = 0; i < n; i++)
        {
            char c = s.charAt(i);
            if(((c >= '0' && c <= '1') || c == '.') == false)
            {
                isName = true;
            }
        }

        if(isName == false)
        {
            try
            {
                return new ASN1ObjectIdentifier(s);
            }catch(IllegalArgumentException e)
            {
            }
        }

        ASN1ObjectIdentifier oid = ObjectIdentifiers.nameToOID(s);
        if(oid == null)
        {
            throw new InvalidOIDorNameException(s);
        }
        return oid;
    }

    public static String signerConfToString(
            String signerConf,
            final boolean verbose,
            final boolean ignoreSensitiveInfo)
    {
        if(ignoreSensitiveInfo)
        {
            signerConf = SecurityUtil.eraseSensitiveData(signerConf);
        }

        if(verbose || signerConf.length() < 101)
        {
            return signerConf;
        }
        else
        {
            return new StringBuilder().append(signerConf.substring(0, 97)).append("...").toString();
        }
    }

    private static String eraseSensitiveData(
            final String conf)
    {
        if(conf == null || conf.contains("password?") == false)
        {
            return conf;
        }

        try
        {
            CmpUtf8Pairs pairs = new CmpUtf8Pairs(conf);
            String value = pairs.getValue("password");
            if(value != null && StringUtil.startsWithIgnoreCase(value, "PBE:") == false)
            {
                pairs.putUtf8Pair("password", "<sensitve>");
            }
            return pairs.getEncoded();
        }catch(Exception e)
        {
            return conf;
        }
    }

    public static ASN1ObjectIdentifier getHashAlg(
            String hashAlgName)
    throws NoSuchAlgorithmException
    {
        hashAlgName = hashAlgName.trim();
        ParamChecker.assertNotBlank("hashAlgName", hashAlgName);
        hashAlgName = hashAlgName.replace("-", "").toUpperCase();

        if("SHA1".equalsIgnoreCase(hashAlgName))
        {
            return X509ObjectIdentifiers.id_SHA1;
        }
        else if("SHA224".equalsIgnoreCase(hashAlgName))
        {
            return NISTObjectIdentifiers.id_sha224;
        }
        else if("SHA256".equalsIgnoreCase(hashAlgName))
        {
            return NISTObjectIdentifiers.id_sha256;
        }
        else if("SHA384".equalsIgnoreCase(hashAlgName))
        {
            return NISTObjectIdentifiers.id_sha384;
        }
        else if("SHA512".equalsIgnoreCase(hashAlgName))
        {
            return NISTObjectIdentifiers.id_sha512;
        }
        else
        {
            throw new NoSuchAlgorithmException("Unsupported hash algorithm " + hashAlgName);
        }
    }

    static public String getSignatureAlgoName(
            final AlgorithmIdentifier sigAlgId)
    throws NoSuchAlgorithmException
    {
        ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();

        if(X9ObjectIdentifiers.ecdsa_with_SHA1.equals(algOid))
        {
            return "SHA1withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA224.equals(algOid))
        {
            return "SHA224withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA256.equals(algOid))
        {
            return "SHA256withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA384.equals(algOid))
        {
            return "SHA384withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA512.equals(algOid))
        {
            return "SHA512withECDSA";
        }
        else if(X9ObjectIdentifiers.id_dsa_with_sha1.equals(algOid))
        {
            return "SHA1withDSA";
        }
        else if(NISTObjectIdentifiers.dsa_with_sha224.equals(algOid))
        {
            return "SHA224withDSA";
        }
        else if(NISTObjectIdentifiers.dsa_with_sha256.equals(algOid))
        {
            return "SHA256withDSA";
        }
        else if(NISTObjectIdentifiers.dsa_with_sha384.equals(algOid))
        {
            return "SHA384withDSA";
        }
        else if(NISTObjectIdentifiers.dsa_with_sha512.equals(algOid))
        {
            return "SHA512withDSA";
        }
        else if(PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid))
        {
            return "SHA1withRSA";
        }
        else if(PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid))
        {
            return "SHA224withRSA";
        }
        else if(PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid))
        {
            return "SHA256withRSA";
        }
        else if(PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid))
        {
            return "SHA384withRSA";
        }
        else if(PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid))
        {
            return "SHA512withRSA";
        }
        else if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid))
        {
            RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigAlgId.getParameters());
            ASN1ObjectIdentifier digestAlgOid = param.getHashAlgorithm().getAlgorithm();
            if(X509ObjectIdentifiers.id_SHA1.equals(digestAlgOid))
            {
                return "SHA1withRSAandMGF1";
            }
            else if(NISTObjectIdentifiers.id_sha256.equals(digestAlgOid))
            {
                return "SHA256withRSAandMGF1";
            }
            else if(NISTObjectIdentifiers.id_sha384.equals(digestAlgOid))
            {
                return "SHA384withRSAandMGF1";
            }
            else if(NISTObjectIdentifiers.id_sha512.equals(digestAlgOid))
            {
                return "SHA512withRSAandMGF1";
            }
            else
            {
                throw new NoSuchAlgorithmException("unsupported digest algorithm " + digestAlgOid.getId());
            }
        }
        else
        {
            throw new NoSuchAlgorithmException("unsupported signature algorithm " + algOid.getId());
        }
    }

    static public AlgorithmIdentifier getSignatureAlgoId(
            final String signatureAlgoName)
    throws NoSuchAlgorithmException
    {
        String algoS = signatureAlgoName.replaceAll("-", "");

        AlgorithmIdentifier signatureAlgId;
        if("SHA1withRSAandMGF1".equalsIgnoreCase(algoS) ||
                "SHA224withRSAandMGF1".equalsIgnoreCase(algoS) ||
                "SHA256withRSAandMGF1".equalsIgnoreCase(algoS) ||
                "SHA384withRSAandMGF1".equalsIgnoreCase(algoS) ||
                "SHA512withRSAandMGF1".equalsIgnoreCase(algoS))
        {
            ASN1ObjectIdentifier hashAlgo;
            if("SHA1withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                hashAlgo = X509ObjectIdentifiers.id_SHA1;
            }
            else if("SHA224withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                hashAlgo = NISTObjectIdentifiers.id_sha224;
            }
            else if("SHA256withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                hashAlgo = NISTObjectIdentifiers.id_sha256;
            }
            else if("SHA384withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                hashAlgo = NISTObjectIdentifiers.id_sha384;
            }
            else if("SHA512withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                hashAlgo = NISTObjectIdentifiers.id_sha512;
            }
            else
            {
                throw new NoSuchAlgorithmException("should not reach here, unknown algorithm " + algoS);
            }

            signatureAlgId = SecurityUtil.buildRSAPSSAlgorithmIdentifier(hashAlgo);
        }
        else
        {
            boolean withNullParam = false;
            ASN1ObjectIdentifier algOid;
            if("SHA1withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA1".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId().equals(algoS))
            {
                algOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
                withNullParam = true;
            }
            else if("SHA224withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA224".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha224WithRSAEncryption.getId().equals(algoS))
            {
                algOid = PKCSObjectIdentifiers.sha224WithRSAEncryption;
                withNullParam = true;
            }
            else if("SHA256withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA256".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId().equals(algoS))
            {
                algOid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
                withNullParam = true;
            }
            else if("SHA384withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA384".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha384WithRSAEncryption.getId().equals(algoS))
            {
                algOid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
                withNullParam = true;
            }
            else if("SHA512withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA512".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha512WithRSAEncryption.getId().equals(algoS))
            {
                algOid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
                withNullParam = true;
            }
            else if("SHA1withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA1".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA1.getId().equals(algoS))
            {
                algOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            }
            else if("SHA224withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA224".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA224.getId().equals(algoS))
            {
                algOid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            }
            else if("SHA256withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA256".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA256.getId().equals(algoS))
            {
                algOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            }
            else if("SHA384withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA384".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA384.getId().equals(algoS))
            {
                algOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            }
            else if("SHA512withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA512".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA512.getId().equals(algoS))
            {
                algOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            }
            else if("SHA1withDSA".equalsIgnoreCase(algoS) || "DSAwithSHA1".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.id_dsa_with_sha1.getId().equals(algoS))
            {
                algOid = X9ObjectIdentifiers.id_dsa_with_sha1;
            }
            else if("SHA224withDSA".equalsIgnoreCase(algoS) || "DSAwithSHA224".equalsIgnoreCase(algoS) ||
                    NISTObjectIdentifiers.dsa_with_sha224.getId().equals(algoS))
            {
                algOid = NISTObjectIdentifiers.dsa_with_sha224;
            }
            else if("SHA256withDSA".equalsIgnoreCase(algoS) || "DSAwithSHA256".equalsIgnoreCase(algoS) ||
                    NISTObjectIdentifiers.dsa_with_sha256.getId().equals(algoS))
            {
                algOid = NISTObjectIdentifiers.dsa_with_sha256;
            }
            else if("SHA384withDSA".equalsIgnoreCase(algoS) || "DSAwithSHA384".equalsIgnoreCase(algoS) ||
                    NISTObjectIdentifiers.dsa_with_sha384.getId().equals(algoS))
            {
                algOid = NISTObjectIdentifiers.dsa_with_sha384;
            }
            else if("SHA512withDSA".equalsIgnoreCase(algoS) || "DSAwithSHA512".equalsIgnoreCase(algoS) ||
                    NISTObjectIdentifiers.dsa_with_sha512.getId().equals(algoS))
            {
                algOid = NISTObjectIdentifiers.dsa_with_sha512;
            }
            else
            {
                throw new NoSuchAlgorithmException("unsupported signature algorithm " + algoS);
            }

            signatureAlgId = withNullParam ? new AlgorithmIdentifier(algOid, DERNull.INSTANCE) :
                new AlgorithmIdentifier(algOid);
        }

        return signatureAlgId;
    }

    static public AlgorithmIdentifier getSignatureAlgoId(
            final PublicKey pubKey,
            final String hashAlgo,
            final boolean mgf1)
    throws NoSuchAlgorithmException
    {
        AlgorithmIdentifier signatureAlgId;
        if(pubKey instanceof RSAPublicKey)
        {
            if(mgf1)
            {
                ASN1ObjectIdentifier hashAlgoOid = SecurityUtil.getHashAlg(hashAlgo);
                signatureAlgId = SecurityUtil.buildRSAPSSAlgorithmIdentifier(hashAlgoOid);
            }
            else
            {
                ASN1ObjectIdentifier sigAlgoOid;
                if("SHA1".equalsIgnoreCase(hashAlgo))
                {
                    sigAlgoOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
                }
                else if("SHA224".equalsIgnoreCase(hashAlgo))
                {
                    sigAlgoOid = PKCSObjectIdentifiers.sha224WithRSAEncryption;
                }
                else if("SHA256".equalsIgnoreCase(hashAlgo))
                {
                    sigAlgoOid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
                }
                else if("SHA384".equalsIgnoreCase(hashAlgo))
                {
                    sigAlgoOid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
                }
                else if("SHA512".equalsIgnoreCase(hashAlgo))
                {
                    sigAlgoOid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
                }
                else
                {
                    throw new RuntimeException("unsupported hash algorithm " + hashAlgo);
                }

                signatureAlgId = new AlgorithmIdentifier(sigAlgoOid, DERNull.INSTANCE);
            }
        }
        else if(pubKey instanceof ECPublicKey)
        {
            ASN1ObjectIdentifier sigAlgoOid;
            if("SHA1".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            }
            else if("SHA224".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            }
            else if("SHA256".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            }
            else if("SHA384".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            }
            else if("SHA512".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            }
            else
            {
                throw new NoSuchAlgorithmException("unsupported hash algorithm " + hashAlgo);
            }

            signatureAlgId = new AlgorithmIdentifier(sigAlgoOid);
        }
        else if(pubKey instanceof DSAPublicKey)
        {
            ASN1ObjectIdentifier sigAlgoOid;
            if("SHA1".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = X9ObjectIdentifiers.id_dsa_with_sha1;
            }
            else if("SHA224".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = NISTObjectIdentifiers.dsa_with_sha224;
            }
            else if("SHA256".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = NISTObjectIdentifiers.dsa_with_sha256;
            }
            else if("SHA384".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = NISTObjectIdentifiers.dsa_with_sha384;
            }
            else if("SHA512".equalsIgnoreCase(hashAlgo))
            {
                sigAlgoOid = NISTObjectIdentifiers.dsa_with_sha512;
            }
            else
            {
                throw new NoSuchAlgorithmException("unsupported hash algorithm " + hashAlgo);
            }

            signatureAlgId = new AlgorithmIdentifier(sigAlgoOid);
        }
        else
        {
            throw new NoSuchAlgorithmException("unsupported key type " + pubKey.getClass().getName());
        }

        return signatureAlgId;
    }

    static public AlgorithmIdentifier extractDigesetAlgorithmIdentifier(
            final AlgorithmIdentifier sigAlgId)
    throws NoSuchAlgorithmException
    {
        ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();

        ASN1ObjectIdentifier digestAlgOid;
        if(X9ObjectIdentifiers.ecdsa_with_SHA1.equals(algOid))
        {
            digestAlgOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA224.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha224;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA256.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha256;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA384.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha384;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA512.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha512;
        }
        else if(X9ObjectIdentifiers.id_dsa_with_sha1.equals(algOid))
        {
            digestAlgOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if(NISTObjectIdentifiers.dsa_with_sha224.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha224;
        }
        else if(NISTObjectIdentifiers.dsa_with_sha256.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha256;
        }
        else if(NISTObjectIdentifiers.dsa_with_sha384.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha384;
        }
        else if(NISTObjectIdentifiers.dsa_with_sha512.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha512;
        }
        else if(PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if(PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha224;
        }
        else if(PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha256;
        }
        else if(PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha384;
        }
        else if(PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha512;
        }
        else if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid))
        {
            ASN1Encodable asn1Encodable = sigAlgId.getParameters();
            RSASSAPSSparams param = RSASSAPSSparams.getInstance(asn1Encodable);
            digestAlgOid = param.getHashAlgorithm().getAlgorithm();
        }
        else
        {
            throw new NoSuchAlgorithmException("unknown signature algorithm" + algOid.getId());
        }

        return new AlgorithmIdentifier(digestAlgOid, DERNull.INSTANCE);
    }

    public static boolean equalsAlgoName(
            String a,
            String b)
    {
        if(a.equalsIgnoreCase(b))
        {
            return true;
        }

        a = a.replace("-", "");
        b = b.replace("-", "");
        boolean equals = a.equalsIgnoreCase(b);
        if(equals)
        {
            return true;
        }

        return splitAlgoNameTokens(a).equals(splitAlgoNameTokens(b));
    }

    private static Set<String> splitAlgoNameTokens(
            String algoName)
    {
        algoName = algoName.toUpperCase();
        int idx = algoName.indexOf("AND");
        Set<String> l = new HashSet<>();

        if(idx == -1)
        {
            l.add(algoName);
            return l;
        }

        final int len = algoName.length();

        int beginIndex = 0;
        int endIndex = idx;
        while(true)
        {
            String token = algoName.substring(beginIndex, endIndex);
            if(StringUtil.isNotBlank(token))
            {
                l.add(token);
            }

            if(endIndex >= len)
            {
                return l;
            }
            beginIndex = endIndex + 3; // 3 = "AND".length()
            endIndex = algoName.indexOf("AND", beginIndex);
            if(endIndex == -1)
            {
                endIndex = len;
            }
        }
    }

    static public AlgorithmIdentifier buildRSAPSSAlgorithmIdentifier(
            final ASN1ObjectIdentifier digAlgOid)
    throws NoSuchAlgorithmException
    {
        RSASSAPSSparams params = createPSSRSAParams(digAlgOid);
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, params);
    }

    static public AlgorithmIdentifier buildDSASigAlgorithmIdentifier(
            final AlgorithmIdentifier digAlgId)
    throws NoSuchAlgorithmException
    {
        ASN1ObjectIdentifier digAlgOid = digAlgId.getAlgorithm();
        ASN1ObjectIdentifier sid;
        if(X509ObjectIdentifiers.id_SHA1.equals(digAlgOid))
        {
            sid = X9ObjectIdentifiers.id_dsa_with_sha1;
        }
        else if(NISTObjectIdentifiers.id_sha224.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha224;
        }
        else if(NISTObjectIdentifiers.id_sha256.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha256;
        }
        else if(NISTObjectIdentifiers.id_sha384.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha384;
        }
        else if(NISTObjectIdentifiers.id_sha512.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha512;
        }
        else
        {
            throw new NoSuchAlgorithmException("no signature algorithm for DSA with digest algorithm " + digAlgOid.getId());
        }
        return new AlgorithmIdentifier(sid);
    }

    static public RSASSAPSSparams createPSSRSAParams(
            final ASN1ObjectIdentifier digestAlgOID)
    throws NoSuchAlgorithmException
    {
        int saltSize;
        if(X509ObjectIdentifiers.id_SHA1.equals(digestAlgOID))
        {
            saltSize = 20;
        }
        else if(NISTObjectIdentifiers.id_sha224.equals(digestAlgOID))
        {
            saltSize = 28;
        }
        else if(NISTObjectIdentifiers.id_sha256.equals(digestAlgOID))
        {
            saltSize = 32;
        }
        else if(NISTObjectIdentifiers.id_sha384.equals(digestAlgOID))
        {
            saltSize = 48;
        }
        else if(NISTObjectIdentifiers.id_sha512.equals(digestAlgOID))
        {
            saltSize = 64;
        }
        else
        {
            throw new NoSuchAlgorithmException(
                    "unknown digest algorithm " + digestAlgOID);
        }

        AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(digestAlgOID, DERNull.INSTANCE);
        return new RSASSAPSSparams(
            digAlgId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digAlgId),
            new ASN1Integer(saltSize),
            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
    }

}
