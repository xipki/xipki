// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class CaIdentifierRequest extends SdkRequest{

  /**
   * SHA-1 fingerprint of the DER-encoded issuer's certificate
   */
  private final byte[] issuerCertSha1Fp;

  private final X500NameType issuer;

  private final byte[] authorityKeyIdentifier;

  protected CaIdentifierRequest(
      byte[] issuerCertSha1Fp, X500NameType issuer,
      byte[] authorityKeyIdentifier) {
    this.issuerCertSha1Fp = issuerCertSha1Fp;
    this.issuer = issuer;
    this.authorityKeyIdentifier = authorityKeyIdentifier;
  }

  public byte[] issuerCertSha1Fp() {
    return issuerCertSha1Fp;
  }

  public X500NameType issuer() {
    return issuer;
  }

  public byte[] authorityKeyIdentifier() {
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
      sb.append("SHA1(cert)=").append(Hex.toHexString(issuerCertSha1Fp))
          .append(",");
    }

    if (authorityKeyIdentifier != null) {
      sb.append("AKI=").append(Hex.toHexString(authorityKeyIdentifier))
          .append(",");
    }
    sb.deleteCharAt(sb.length() - 1);
    sb.append(")");

    return sb.toString();
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encode0(encoder, 0);
  }

  protected void encode0(CborEncoder encoder, int subClassFieldSize)
      throws CodecException {
    encoder.writeArrayStart(3 + subClassFieldSize)
        .writeByteString(issuerCertSha1Fp)
        .writeObject(issuer).writeByteString(authorityKeyIdentifier);
  }

  public static CaIdentifierRequest decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("CaIdentifierRequest", decoder, 3);
      return new CaIdentifierRequest(
          decoder.readByteString(), X500NameType.decode(decoder),
          decoder.readByteString());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, CaIdentifierRequest.class), ex);
    }
  }

}
