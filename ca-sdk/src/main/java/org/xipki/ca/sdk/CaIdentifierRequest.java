// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class CaIdentifierRequest extends SdkRequest{

  /**
   * SHA-1 fingerprint of the DER-encoded issuer's certificate
   */
  private final byte[] issuerCertSha1Fp;

  private final X500NameType issuer;

  private final byte[] authorityKeyIdentifier;

  protected CaIdentifierRequest(byte[] issuerCertSha1Fp, X500NameType issuer, byte[] authorityKeyIdentifier) {
    this.issuerCertSha1Fp = issuerCertSha1Fp;
    this.issuer = Args.notNull(issuer, "issuer");
    this.authorityKeyIdentifier = authorityKeyIdentifier;
  }

  public byte[] getIssuerCertSha1Fp() {
    return issuerCertSha1Fp;
  }

  public X500NameType getIssuer() {
    return issuer;
  }

  public byte[] getAuthorityKeyIdentifier() {
    return authorityKeyIdentifier;
  }

  public String idText() {
    StringBuilder sb = new StringBuilder();
    sb.append("(");
    if (issuer != null) {
      // issuer of certificate is the subject of CA
      sb.append("subject=");
      try {
        sb.append(X509Util.x500NameText(issuer.toX500Name()));
      } catch (IOException ex) {
        sb.append("<ERROR>");
      }
      sb.append(",");
    }

    if (issuerCertSha1Fp != null) {
      sb.append("SHA1(cert)=").append(Hex.toHexString(issuerCertSha1Fp)).append(",");
    }

    if (authorityKeyIdentifier != null) {
      sb.append("AKI=").append(Hex.toHexString(authorityKeyIdentifier)).append(",");
    }
    sb.deleteCharAt(sb.length() - 1);
    sb.append(")");

    return sb.toString();
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    encode(encoder, 0);
  }

  protected void encode(CborEncoder encoder, int subClassFieldSize) throws EncodeException {
    try {
      encoder.writeArrayStart(3 + subClassFieldSize);
      encoder.writeByteString(issuerCertSha1Fp);
      encoder.writeObject(issuer);
      encoder.writeByteString(authorityKeyIdentifier);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static CaIdentifierRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("CaIdentifierRequest", decoder, 3);
      return new CaIdentifierRequest(
          decoder.readByteString(),
          X500NameType.decode(decoder),
          decoder.readByteString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + CaIdentifierRequest.class.getName(), ex);
    }
  }

}
