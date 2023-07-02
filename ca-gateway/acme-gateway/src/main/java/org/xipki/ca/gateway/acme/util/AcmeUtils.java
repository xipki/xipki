/*
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
import org.xipki.ca.gateway.acme.AcmeProtocolException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.xipki.util.Base64Url.decodeFast;

import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.net.IDN;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Contains utility methods that are frequently used for the ACME protocol.
 * <p>
 * This class is internal. You may use it in your own code, but be warned that methods may
 * change their signature or disappear without prior announcement.
 */
public final class AcmeUtils {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final String ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:";

    private static final Pattern DATE_PATTERN = Pattern.compile(
                    "^(\\d{4})-(\\d{2})-(\\d{2})T"
                  + "(\\d{2}):(\\d{2}):(\\d{2})"
                  + "(?:\\.(\\d{1,3})\\d*)?"
                  + "(Z|[+-]\\d{2}:?\\d{2})$", Pattern.CASE_INSENSITIVE);

    private static final Pattern TZ_PATTERN = Pattern.compile(
                "([+-])(\\d{2}):?(\\d{2})$");

    private static final Pattern CONTENT_TYPE_PATTERN = Pattern.compile(
                "([^;]+)(?:;.*?charset=(\"?)([a-z0-9_-]+)(\\2))?.*", Pattern.CASE_INSENSITIVE);

    private static final Pattern MAIL_PATTERN = Pattern.compile("\\?|@.*,");

    private static final Pattern BASE64URL_PATTERN = Pattern.compile("[0-9A-Za-z_-]*");

    private static final Base64.Encoder PEM_ENCODER = Base64.getMimeEncoder(64,
                "\n".getBytes(StandardCharsets.US_ASCII));
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    /**
     * Enumeration of PEM labels.
     */
    public enum PemLabel {
        CERTIFICATE("CERTIFICATE"),
        CERTIFICATE_REQUEST("CERTIFICATE REQUEST"),
        PRIVATE_KEY("PRIVATE KEY"),
        PUBLIC_KEY("PUBLIC KEY");

        private final String label;

        PemLabel(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }


    private AcmeUtils() {
        // Utility class without constructor
    }

    /**
     * Computes a SHA-256 hash of the given string.
     *
     * @param z
     *            String to hash
     * @return Hash
     */
    public static byte[] sha256hash(String z) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(z.getBytes(UTF_8));
            return md.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new AcmeProtocolException("Could not compute hash", ex);
        }
    }

    /**
     * Hex encodes the given byte array.
     *
     * @param data
     *            byte array to hex encode
     * @return Hex encoded string of the data (with lower case characters)
     */
    public static String hexEncode(byte[] data) {
        char[] result = new char[data.length * 2];
        for (int ix = 0; ix < data.length; ix++) {
            int val = data[ix] & 0xFF;
            result[ix * 2] = HEX[val >>> 4];
            result[ix * 2 + 1] = HEX[val & 0x0F];
        }
        return new String(result);
    }

    /**
     * Base64 encodes the given byte array, using URL style encoding.
     *
     * @param data
     *            byte array to base64 encode
     * @return base64 encoded string
     */
    public static String base64UrlEncode(byte[] data) {
        return URL_ENCODER.encodeToString(data);
    }

    /**
     * Base64 decodes to a byte array, using URL style encoding.
     *
     * @param base64
     *            base64 encoded string
     * @return decoded data
     */
    public static byte[] base64UrlDecode(String base64) {
        return URL_DECODER.decode(base64);
    }

    /**
     * Validates that the given {@link String} is a valid base64url encoded value.
     *
     * @param base64
     *            {@link String} to validate
     * @return {@code true}: String contains a valid base64url encoded value.
     *         {@code false} if the {@link String} was {@code null} or contained illegal
     *         characters.
     * @since 2.6
     */
    public static boolean isValidBase64Url(String base64) {
        return base64 != null && BASE64URL_PATTERN.matcher(base64).matches();
    }

    /**
     * ASCII encodes a domain name.
     * <p>
     * The conversion is done as described in
     * <a href="http://www.ietf.org/rfc/rfc3490.txt">RFC 3490</a>. Additionally, all
     * leading and trailing white spaces are trimmed, and the result is lowercased.
     * <p>
     * It is safe to pass in ACE encoded domains, they will be returned unchanged.
     *
     * @param domain
     *            Domain name to encode
     * @return Encoded domain name, white space trimmed and lower cased.
     */
    public static String toAce(String domain) {
        Objects.requireNonNull(domain, "domain");
        return IDN.toASCII(domain.trim()).toLowerCase();
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

    /**
     * Converts the given locale to an Accept-Language header value.
     *
     * @param locale
     *         {@link Locale} to be used in the header
     * @return Value that can be used in an Accept-Language header
     */
    public static String localeToLanguageHeader(Locale locale) {
        if (locale == null || "und".equals(locale.toLanguageTag())) {
            return "*";
        }

        String langTag = locale.toLanguageTag();

        StringBuilder header = new StringBuilder(langTag);
        if (langTag.indexOf('-') >= 0) {
            header.append(',').append(locale.getLanguage()).append(";q=0.8");
        }
        header.append(",*;q=0.1");

        return header.toString();
    }

    /**
     * Strips the acme error prefix from the error string.
     * <p>
     * For example, for "urn:ietf:params:acme:error:unauthorized", "unauthorized" is
     * returned.
     *
     * @param type
     *            Error type to strip the prefix from. {@code null} is safe.
     * @return Stripped error type, or {@code null} if the prefix was not found.
     */
    public static String stripErrorPrefix(String type) {
        if (type != null && type.startsWith(ACME_ERROR_PREFIX)) {
            return type.substring(ACME_ERROR_PREFIX.length());
        } else {
            return null;
        }
    }

    /**
     * Writes an encoded key or certificate to a file in PEM format.
     *
     * @param encoded
     *            Encoded data to write
     * @param label
     *            {@link PemLabel} to be used
     * @param out
     *            {@link Writer} to write to. It will not be closed after use!
     */
    public static void writeToPem(byte[] encoded, PemLabel label, Writer out)
                throws IOException {
        out.append("-----BEGIN ").append(label.toString()).append("-----\n");
        out.append(new String(PEM_ENCODER.encode(encoded), StandardCharsets.US_ASCII));
        out.append("\n-----END ").append(label.toString()).append("-----\n");
    }

    /**
     * Extracts the content type of a Content-Type header.
     *
     * @param header
     *            Content-Type header
     * @return Content-Type, or {@code null} if the header was invalid or empty
     * @throws AcmeProtocolException
     *             if the Content-Type header contains a different charset than "utf-8".
     */
    public static String getContentType(String header) {
        if (header != null) {
            Matcher m = CONTENT_TYPE_PATTERN.matcher(header);
            if (m.matches()) {
                String charset = m.group(3);
                if (charset != null && !"utf-8".equalsIgnoreCase(charset)) {
                    throw new AcmeProtocolException("Unsupported charset " + charset);
                }
                return m.group(1).trim().toLowerCase();
            }
        }
        return null;
    }

    /**
     * Validates a contact {@link URI}.
     *
     * @param contact
     *            Contact {@link URI} to validate
     * @throws IllegalArgumentException
     *             if the contact {@link URI} is not suitable for account contacts.
     */
    public static void validateContact(URI contact) {
        if ("mailto".equalsIgnoreCase(contact.getScheme())) {
            String address = contact.toString().substring(7);
            if (MAIL_PATTERN.matcher(address).find()) {
                throw new IllegalArgumentException(
                        "multiple recipients or hfields are not allowed: " + contact);
            }
        }
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

    public static Map<String, String> jsonToMap(AcmeJson json) {
        Map<String, String> map = new HashMap<>();
        for (String name : json.keySet()) {
            map.put(name, json.get(name).asString());
        }
        return map;
    }

}
