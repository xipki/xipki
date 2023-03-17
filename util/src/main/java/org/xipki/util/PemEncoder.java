// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

/**
 * PEM encoder. For details please refer to RFC 7468.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class PemEncoder {

  public enum PemLabel {
    /**
     * RFC5280 Certificate.
     */
    CERTIFICATE("CERTIFICATE"),

    /**
     * RFC 5280 CertificateList.
     */
    X509_CRL("X509 CRL"),

    /**
     * RFC 2986 CertificationRequest.
     */
    CERTIFICATE_REQUEST("CERTIFICATE REQUEST"),

    /**
     * RFC 2315 ContentInfo.
     */
    PKCS7("PKCS7"),

    /**
     * RFC 5652 ContentInfo.
     */
    CMS("CMS"),

    /**
     * RFC 5208 PrivateKeyInfo / RFC 5958 OneAsymmetricKey.
     */
    PRIVATE_KEY("PRIVATE KEY"),

    /**
     * RFC 5958 EncryptedPrivateKeyInfo.
     */
    ENCRYPTED_PRIVATE_KEY("ENCRYPTED PRIVATE KEY"),

    /**
     * RFC 5755 AttributeCertificate.
     */
    ATTRIBUTE_CERTIFICATE("ATTRIBUTE CERTIFICATE"),

    /**
     * RFC 5280 SubjectPublicKeyInfo.
     */
    PUBLIC_KEY("PUBLIC KEY");

    private final byte[] prefix;

    private final byte[] postfix;

    private final String type;

    PemLabel(String type) {
      this.type = type;
      this.prefix = StringUtil.toUtf8Bytes("-----BEGIN " + type + "-----\r\n");
      this.postfix = StringUtil.toUtf8Bytes("\r\n-----END " + type + "-----");
    }

    public String getType() {
      return type;
    }

  }

  public static byte[] encode(byte[] data, PemLabel pemLabel) {
    byte[] base64 = Base64.encodeToPemByte(data);
    byte[] out = new byte[pemLabel.prefix.length + base64.length + pemLabel.postfix.length];
    System.arraycopy(pemLabel.prefix, 0, out, 0, pemLabel.prefix.length);
    System.arraycopy(base64, 0, out, pemLabel.prefix.length, base64.length);
    System.arraycopy(pemLabel.postfix, 0, out, pemLabel.prefix.length + base64.length,
        pemLabel.postfix.length);
    return out;
  }

}
