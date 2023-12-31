// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Pack;
import org.xipki.ca.gateway.acme.type.AcmeError;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Base64Url;
import org.xipki.util.DateUtil;
import org.xipki.util.http.HttpStatusCode;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.xipki.util.Base64Url.decodeFast;

/**
 * ACME Utility classs
 * @author Lijun Liao (xipki)
 */
final class AcmeUtils {

    private AcmeUtils() {
        // Utility class without constructor
    }

    public static Instant parseTimestamp(String timestamp) throws AcmeProtocolException {
        try {
            return DateUtil.parseRFC3339Timestamp(timestamp);
        } catch (DateTimeParseException ex) {
            throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST, AcmeError.malformed,
                "invalid timestamp " + timestamp);
        }
    }

    public static PublicKey jwkPublicKey(Map<String, String> jwk) throws InvalidKeySpecException {
        String kty = jwk.get("kty");
        if ("RSA".equalsIgnoreCase(kty)) {
            return KeyUtil.generateRSAPublicKey(new RSAPublicKeySpec(
                new BigInteger(1, decodeFast(jwk.get("n"))), new BigInteger(1, decodeFast(jwk.get("e")))));
        } else if ("EC".equalsIgnoreCase(kty)) {
            String curveName = jwk.get("crv");
            ASN1ObjectIdentifier curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
            byte[] encodedPoint = buildECPublicKeyData(curveOid, decodeFast(jwk.get("x")), decodeFast(jwk.get("y")));
            return KeyUtil.createECPublicKey(curveOid, encodedPoint);
        } else {
            throw new InvalidKeySpecException("unsupported kty " + kty);
        }
    }

    public static boolean matchKey(Map<String, String> jwk, SubjectPublicKeyInfo pkInfo)
        throws InvalidKeySpecException {
        AlgorithmIdentifier pkInfoAlgo = pkInfo.getAlgorithm();
        ASN1ObjectIdentifier pkKeyAlgo = pkInfoAlgo.getAlgorithm();

        String kty = jwk.get("kty");
        if ("RSA".equalsIgnoreCase(kty)) {
            if (!(pkKeyAlgo.equals(PKCSObjectIdentifiers.rsaEncryption)
                || pkKeyAlgo.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)
                || pkKeyAlgo.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption)
                || pkKeyAlgo.equals(PKCSObjectIdentifiers.sha224WithRSAEncryption)
                || pkKeyAlgo.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)
                || pkKeyAlgo.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption)
                || pkKeyAlgo.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption))) {
                return false;
            }

            BigInteger n = new BigInteger(1, decodeFast(jwk.get("n")));
            BigInteger e = new BigInteger(1, decodeFast(jwk.get("e")));

            ASN1Sequence seq = ASN1Sequence.getInstance(pkInfo.getPublicKeyData().getOctets());
            BigInteger n2 = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
            BigInteger e2 = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
            return n.equals(n2) && e.equals(e2);
        } else if ("EC".equalsIgnoreCase(kty)) {
            if (!X9ObjectIdentifiers.id_ecPublicKey.equals(pkKeyAlgo)) {
                return false;
            }

            ASN1ObjectIdentifier curveOid2;
            try {
                curveOid2 = ASN1ObjectIdentifier.getInstance(pkInfoAlgo.getParameters());
            } catch (IllegalArgumentException ex) {
                return false;
            }

            String curveName = jwk.get("crv");
            ASN1ObjectIdentifier curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
            if (!curveOid2.equals(curveOid)) {
                return false;
            }

            byte[] encodedPoint = buildECPublicKeyData(curveOid, decodeFast(jwk.get("x")), decodeFast(jwk.get("y")));
            return Arrays.equals(pkInfo.getPublicKeyData().getBytes(), encodedPoint);
        } else {
            throw new RuntimeException("unsupported kty " + kty);
        }
    }

    private static byte[] buildECPublicKeyData(ASN1ObjectIdentifier curveOid, byte[] x, byte[] y)
        throws InvalidKeySpecException {
        int fieldSize;
        if (SECObjectIdentifiers.secp192r1.equals(curveOid)
            || TeleTrusTObjectIdentifiers.brainpoolP192r1.equals(curveOid)) {
            fieldSize = 24;
        } else if (SECObjectIdentifiers.secp224r1.equals(curveOid)
            || TeleTrusTObjectIdentifiers.brainpoolP224r1.equals(curveOid)) {
            fieldSize = 28;
        } else if (SECObjectIdentifiers.secp256r1.equals(curveOid)
            || TeleTrusTObjectIdentifiers.brainpoolP256r1.equals(curveOid)
            || GMObjectIdentifiers.sm2p256v1.equals(curveOid)) {
            fieldSize = 32;
        } else if (SECObjectIdentifiers.secp384r1.equals(curveOid)
            || TeleTrusTObjectIdentifiers.brainpoolP384r1.equals(curveOid)) {
            fieldSize = 48;
        } else if (TeleTrusTObjectIdentifiers.brainpoolP256r1.equals(curveOid)) {
            fieldSize = 64;
        } else if (SECObjectIdentifiers.secp521r1.equals(curveOid)) {
            fieldSize = 66;
        } else {
            // guess
            fieldSize = Math.max(x.length, y.length);
        }

        byte[] res = new byte[1 + 2 * fieldSize];
        res[0] = 0x04;
        // x
        int off = 1;
        if (x.length > fieldSize) {
            for (int i = 0; i < x.length - fieldSize; i++) {
                if (x[i] != 0) {
                    throw new InvalidKeySpecException("x too large");
                }
            }
            System.arraycopy(x, x.length - fieldSize, res, off, fieldSize);
        } else {
            System.arraycopy(x, 0, res, off + fieldSize - x.length, x.length);
        }

        // y
        off = 1 + fieldSize;
        if (y.length > fieldSize) {
            for (int i = 0; i < y.length - fieldSize; i++) {
                if (y[i] != 0) {
                    throw new InvalidKeySpecException("y too large");
                }
            }
            System.arraycopy(y, y.length - fieldSize, res, off, fieldSize);
        } else {
            System.arraycopy(y, 0, res, off + fieldSize - y.length, x.length);
        }

        return res;
    }

    public static String toBase64(long label) {
        return Base64Url.encodeToStringNoPadding(Pack.longToLittleEndian(label));
    }

    public static String jwkSha256(Map<String, String> jwk) {
        List<String> jwkNames = new ArrayList<>(jwk.keySet());
        Collections.sort(jwkNames);
        StringBuilder canonJwk = new StringBuilder();
        canonJwk.append("{");
        for (String jwkName : jwkNames) {
            canonJwk.append("\"").append(jwkName).append("\":\"").append(jwk.get(jwkName)).append("\",");
        }
        // remove the last ","
        canonJwk.deleteCharAt(canonJwk.length() - 1);
        canonJwk.append("}");

        return Base64Url.encodeToStringNoPadding(
            HashAlgo.SHA256.hash(canonJwk.toString().getBytes(StandardCharsets.UTF_8)));
    }

    public static Long getLong(Map<String, Object> map, String name) {
        Object obj = map.get(name);
        if (obj == null) {
            return null;
        }
        if (obj instanceof Integer){
            return (long) ((int) obj);
        } else {
            return (Long) obj;
        }
    }

    public static Integer getInt(Map<String, Object> map, String name) {
        Object obj = map.get(name);
        if (obj == null) {
            return null;
        }
        if (obj instanceof Long){
            long l = (long) obj;
            if (l > Integer.MAX_VALUE || l < Integer.MIN_VALUE) {
                throw new IllegalStateException("value of " + name + " is outside the integer range");
            }
            return (int) l;
        } else {
            return (Integer) obj;
        }
    }

}
