// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.codec.asn1.crypto.RSAPublicKey;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.util.Pack;
import org.xipki.ca.gateway.acme.type.AcmeError;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.misc.DateUtil;

import java.math.BigInteger;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * ACME Utility class
 *
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
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
        AcmeError.malformed, "invalid timestamp " + timestamp);
    }
  }

  public static PublicKey jwkPublicKey(Map<String, String> jwk) throws InvalidKeySpecException {
    // RFC 7517, Section 4.1: kty is case-sensitive.
    String kty = jwk.get("kty");
    if ("RSA".equals(kty)) {
      return KeyUtil.getRSAPublicKey(new RSAPublicKeySpec(
        new BigInteger(1, decodeJwkMember(jwk, "n")),
        new BigInteger(1, decodeJwkMember(jwk, "e"))));
    } else if ("EC".equals(kty)) {
      String curveName = jwk.get("crv");
      EcCurveEnum curve = EcCurveEnum.ofAlias(curveName);
      if (curve != null) {
        byte[] encodedPoint = buildECPublicKeyData(curve,
          decodeJwkMember(jwk, "x"), decodeJwkMember(jwk, "y"));
        return KeyUtil.createECPublicKey(curve, encodedPoint);
      }
    }

    throw new InvalidKeySpecException("unsupported kty " + kty);
  }

  public static boolean matchKey(Map<String, String> jwk, SubjectPublicKeyInfo pkInfo)
    throws InvalidKeySpecException {
    AlgorithmIdentifier pkInfoAlgo = pkInfo.getAlgorithm();
    Asn1Oid pkKeyAlgo = pkInfoAlgo.getAlgorithm();

    String kty = jwk.get("kty");
    if ("RSA".equalsIgnoreCase(kty)) {
      if (!( pkKeyAlgo.equals(AlgorithmOIDs.id_rsaEncryption)
        || pkKeyAlgo.equals(AlgorithmOIDs.id_RSASSA_PSS)
        || pkKeyAlgo.equals(AlgorithmOIDs.sha1WithRSAEncryption)
        || pkKeyAlgo.equals(AlgorithmOIDs.sha224WithRSAEncryption)
        || pkKeyAlgo.equals(AlgorithmOIDs.sha256WithRSAEncryption)
        || pkKeyAlgo.equals(AlgorithmOIDs.sha384WithRSAEncryption)
        || pkKeyAlgo.equals(AlgorithmOIDs.sha512WithRSAEncryption))) {
        return false;
      }

      BigInteger n = new BigInteger(1, Base64.decodeFast(jwk.get("n")));
      BigInteger e = new BigInteger(1, Base64.decodeFast(jwk.get("e")));

      RSAPublicKey rsaPublicKey;
      try {
        rsaPublicKey = RSAPublicKey.fromEncoded(pkInfo.subjectPublicKey());
      } catch (CodecException ex) {
        throw new InvalidKeySpecException(ex);
      }

      return n.equals(rsaPublicKey.modulus()) && e.equals(rsaPublicKey.publicExponent());
    } else if ("EC".equalsIgnoreCase(kty)) {
      if (!AlgorithmOIDs.id_ecPublicKey.equals(pkKeyAlgo)) {
        return false;
      }

      Asn1Oid curveOid2;
      try {
        curveOid2 = (Asn1Oid) pkInfoAlgo.getParameters();
      } catch (IllegalArgumentException ex) {
        return false;
      }

      String curveName = jwk.get("crv");
      EcCurveEnum curve = EcCurveEnum.ofAlias(curveName);
      if (curve == null || !curveOid2.equals(curve.oid())) {
        return false;
      }

      byte[] encodedPoint = buildECPublicKeyData(curve,
        Base64.decodeFast(jwk.get("x")), Base64.decodeFast(jwk.get("y")));
      return Arrays.equals(pkInfo.subjectPublicKey(), encodedPoint);
    } else {
      throw new RuntimeException("unsupported kty " + kty);
    }
  }

  private static byte[] decodeJwkMember(Map<String, String> jwk, String name)
      throws InvalidKeySpecException {
    String value = jwk.get(name);
    if (value == null) {
      throw new InvalidKeySpecException("JWK member " + name + " is not present");
    }

    try {
      return java.util.Base64.getUrlDecoder().decode(value);
    } catch (IllegalArgumentException ex) {
      throw new InvalidKeySpecException("JWK member " + name + " is not base64url-encoded");
    }
  }

  /**
   * Decodes the base64url-encoded text.
   * @param text the base64url-encoded text.
   * @param name name of the text, used in the error message.
   * @return the decoded bytes.
   * @throws AcmeProtocolException if text is absent or not base64url-encoded.
   */
  public static byte[] decodeBase64Url(String text, String name) throws AcmeProtocolException {
    if (text == null) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST, AcmeError.malformed,
          name + " is not present");
    }

    try {
      return java.util.Base64.getUrlDecoder().decode(text);
    } catch (IllegalArgumentException ex) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST, AcmeError.malformed,
          name + " is not base64url-encoded");
    }
  }

  /**
   * Decodes the base64url-encoded text.
   * @param text the base64url-encoded text.
   * @return the decoded bytes, or {@code null} if text is not base64url-encoded.
   */
  public static byte[] decodeBase64UrlOrNull(String text) {
    try {
      return java.util.Base64.getUrlDecoder().decode(text);
    } catch (IllegalArgumentException ex) {
      return null;
    }
  }

  /**
   * Converts the JWS ECDSA signature (R || S, RFC 7518 Section 3.4) to the DER-encoded one.
   * @param sig the JWS ECDSA signature.
   * @param fieldByteSize byte size of R and S.
   * @return the DER-encoded signature.
   * @throws AcmeProtocolException if the signature has an invalid length.
   */
  public static byte[] ecdsaJwsSigToDer(byte[] sig, int fieldByteSize)
      throws AcmeProtocolException {
    if (sig.length != 2 * fieldByteSize) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST, AcmeError.malformed,
          "signature is not valid");
    }

    BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, fieldByteSize));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, fieldByteSize, sig.length));
    return new DssSigValue(r, s).getEncoded();
  }

  private static byte[] buildECPublicKeyData(EcCurveEnum curve, byte[] x, byte[] y)
    throws InvalidKeySpecException {
    int fieldSize = curve.fieldByteSize();
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
      System.arraycopy(y, 0, res, off + fieldSize - y.length, y.length);
    }

    return res;
  }

  public static String toBase64(long label) {
    return Base64.getUrlNoPaddingEncoder().encodeToString(Pack.longToLittleEndian(label));
  }

  /**
   * Computes the JWK SHA-256 thumbprint as specified in RFC 7638.
   * @param jwk the JWK.
   * @return the base64url-encoded thumbprint.
   * @throws IllegalArgumentException if a required member is absent.
   */
  public static String jwkSha256(Map<String, String> jwk) {
    String kty = jwk.get("kty");
    // RFC 7638, Section 3.2: only the required members, in lexicographic order.
    List<String> jwkNames;
    if ("EC".equals(kty)) {
      jwkNames = Arrays.asList("crv", "kty", "x", "y");
    } else if ("RSA".equals(kty)) {
      jwkNames = Arrays.asList("e", "kty", "n");
    } else if ("OKP".equals(kty)) {
      jwkNames = Arrays.asList("crv", "kty", "x");
    } else if ("oct".equals(kty)) {
      jwkNames = Arrays.asList("k", "kty");
    } else {
      throw new IllegalArgumentException("unsupported kty " + kty);
    }

    StringBuilder canonJwk = new StringBuilder();
    canonJwk.append("{");
    for (String jwkName : jwkNames) {
      String value = jwk.get(jwkName);
      if (value == null) {
        throw new IllegalArgumentException("JWK member " + jwkName + " is not present");
      }

      // the value is written without escaping, it must contain only Base64 / Base64Url chars.
      if (!Base64.containsOnlyValidChars(value.getBytes(StandardCharsets.UTF_8))) {
        throw new IllegalArgumentException("JWK member " + jwkName
            + " is not Base64 or Base64Url encoded");
      }
      canonJwk.append("\"").append(jwkName).append("\":\"").append(value).append("\",");
    }
    // remove the last ","
    canonJwk.deleteCharAt(canonJwk.length() - 1);
    canonJwk.append("}");

    return Base64.getUrlNoPaddingEncoder().encodeToString(
        HashAlgo.SHA256.hash(canonJwk.toString().getBytes(StandardCharsets.UTF_8)));
  }

  public static String normalizeAndValidateDnsIdentifier(String value)
      throws AcmeProtocolException {
    if (value == null) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "identifier must not be null");
    }

    String text = value.trim();
    boolean wildcard = text.startsWith("*.");
    String host = wildcard ? text.substring(2) : text;
    host = host.toLowerCase();

    if (host.isEmpty()) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "identifier host is empty");
    }

    if (host.endsWith(".")) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "identifier must not end with '.'");
    }

    if ("localhost".equals(host) || host.endsWith(".localhost")) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "localhost identifiers are not permitted");
    }

    if (isIpLiteral(host)) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "IP literal identifiers are not permitted");
    }

    String asciiHost;
    try {
      asciiHost = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES);
    } catch (IllegalArgumentException ex) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "invalid identifier '" + value + "'");
    }

    if (asciiHost.length() > 253) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "identifier is too long");
    }

    String[] labels = asciiHost.split("\\.");
    if (labels.length < 2) {
      throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
          AcmeError.unsupportedIdentifier, "identifier must be a fully qualified domain name");
    }

    for (String label : labels) {
      int n = label.length();
      if (n < 1 || n > 63) {
        throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
            AcmeError.unsupportedIdentifier, "invalid identifier label length");
      }

      if (label.charAt(0) == '-' || label.charAt(n - 1) == '-') {
        throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
            AcmeError.unsupportedIdentifier, "identifier label must not start or end with '-'");
      }

      for (int i = 0; i < n; i++) {
        char ch = label.charAt(i);
        boolean ok = (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9')
            || ch == '-';
        if (!ok) {
          throw new AcmeProtocolException(HttpStatusCode.SC_BAD_REQUEST,
              AcmeError.unsupportedIdentifier, "identifier contains invalid character");
        }
      }
    }

    return wildcard ? "*." + asciiHost : asciiHost;
  }

  private static boolean isIpLiteral(String host) {
    if (host.startsWith("[") || host.endsWith("]") || host.indexOf(':') != -1) {
      return true;
    }

    String[] blocks = host.split("\\.");
    if (blocks.length != 4) {
      return false;
    }

    for (String block : blocks) {
      if (block.isEmpty() || block.length() > 3) {
        return false;
      }

      int v = 0;
      for (int i = 0; i < block.length(); i++) {
        char ch = block.charAt(i);
        if (ch < '0' || ch > '9') {
          return false;
        }
        v = v * 10 + (ch - '0');
      }

      if (v > 255) {
        return false;
      }
    }

    return true;
  }

}
