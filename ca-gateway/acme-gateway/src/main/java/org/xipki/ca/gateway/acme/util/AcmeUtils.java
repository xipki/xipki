/*
 * #THIRDPARTY#
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.xipki.ca.gateway.acme.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Pack;
import org.xipki.ca.gateway.acme.AcmeProtocolException;
import org.xipki.ca.gateway.acme.AcmeSystemException;
import org.xipki.security.HashAlgo;
import org.xipki.security.asn1.Asn1StreamParser;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Base64Url;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.xipki.util.Base64Url.decodeFast;

/**
 * Contains utility methods that are frequently used for the ACME protocol.
 * <p>
 * This class is internal. You may use it in your own code, but be warned that methods may
 * change their signature or disappear without prior announcement.
 * @author ACME4J team
 */
public final class AcmeUtils {
    private static final Pattern DATE_PATTERN = Pattern.compile(
                    "^(\\d{4})-(\\d{2})-(\\d{2})T"
                  + "(\\d{2}):(\\d{2}):(\\d{2})"
                  + "(?:\\.(\\d{1,3})\\d*)?"
                  + "(Z|[+-]\\d{2}:?\\d{2})$", Pattern.CASE_INSENSITIVE);

    private static final Pattern TZ_PATTERN = Pattern.compile(
                "([+-])(\\d{2}):?(\\d{2})$");

    private AcmeUtils() {
        // Utility class without constructor
    }

    /**
     * Parses a RFC 3339 formatted date.
     *
     * @param str
     *            Date string
     * @return {@link Instant} that was parsed
     * @throws IllegalArgumentException
     *             if the date string was not RFC 3339 formatted
     * @see <a href="https://www.ietf.org/rfc/rfc3339.txt">RFC 3339</a>
     */
    public static Instant parseTimestamp(String str) {
        Matcher m = DATE_PATTERN.matcher(str);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal date: " + str);
        }

        int year = Integer.parseInt(m.group(1));
        int month = Integer.parseInt(m.group(2));
        int dom = Integer.parseInt(m.group(3));
        int hour = Integer.parseInt(m.group(4));
        int minute = Integer.parseInt(m.group(5));
        int second = Integer.parseInt(m.group(6));

        StringBuilder msStr = new StringBuilder();
        if (m.group(7) != null) {
            msStr.append(m.group(7));
        }
        while (msStr.length() < 3) {
            msStr.append('0');
        }
        int ms = Integer.parseInt(msStr.toString());

        String tz = m.group(8);
        if ("Z".equalsIgnoreCase(tz)) {
            tz = "GMT";
        } else {
            tz = TZ_PATTERN.matcher(tz).replaceAll("GMT$1$2:$3");
        }

        return ZonedDateTime.of(
                year, month, dom, hour, minute, second, ms * 1_000_000,
                ZoneId.of(tz)).toInstant();
    }

    public static PublicKey jwkPublicKey(Map<String, String> jwk) throws InvalidKeySpecException {
        String kty = jwk.get("kty");
        if ("RSA".equalsIgnoreCase(kty)) {
            BigInteger n = new BigInteger(1, decodeFast(jwk.get("n")));
            BigInteger e = new BigInteger(1, decodeFast(jwk.get("e")));
            return KeyUtil.generateRSAPublicKey(new RSAPublicKeySpec(n, e));
        } else if ("EC".equalsIgnoreCase(kty)) {
            String curveName = jwk.get("crv");
            ASN1ObjectIdentifier curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
            byte[] x = decodeFast(jwk.get("x"));
            byte[] y = decodeFast(jwk.get("y"));
            byte[] encodedPoint = buildECPublicKeyData(curveOid, x, y);
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
            BigInteger e2 = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
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

            byte[] x = decodeFast(jwk.get("x"));
            byte[] y = decodeFast(jwk.get("y"));
            byte[] encodedPoint = buildECPublicKeyData(curveOid, x, y);
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

    public static Map<String, String> jsonToMap(AcmeJson json) throws AcmeProtocolException {
        Map<String, String> map = new HashMap<>();
        for (String name : json.keySet()) {
            map.put(name, json.get(name).asString());
        }
        return map;
    }

    public static String toBase64(long label) {
        return Base64Url.encodeToStringNoPadding(Pack.longToLittleEndian(label));
    }

    public static String toBase64(int label) {
        return Base64Url.encodeToStringNoPadding(Pack.intToLittleEndian(label));
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
            HashAlgo.SHA256.hash(canonJwk.toString().getBytes(UTF_8)));
    }

}
