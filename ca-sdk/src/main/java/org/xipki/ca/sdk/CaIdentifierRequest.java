// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.util.JSON;
import org.xipki.security.util.X509Util;

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
  private byte[] issuerCertSha1Fp;

  private X500NameType issuer;

  private byte[] authorityKeyIdentifier;

  public X500NameType getIssuer() {
    return issuer;
  }

  public void setIssuer(X500NameType issuer) {
    this.issuer = issuer;
  }

  public byte[] getAuthorityKeyIdentifier() {
    return authorityKeyIdentifier;
  }

  public void setAuthorityKeyIdentifier(byte[] authorityKeyIdentifier) {
    this.authorityKeyIdentifier = authorityKeyIdentifier;
  }

  public byte[] getIssuerCertSha1Fp() {
    return issuerCertSha1Fp;
  }

  public void setIssuerCertSha1Fp(byte[] issuerCertSha1Fp) {
    this.issuerCertSha1Fp = issuerCertSha1Fp;
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

  public static CaIdentifierRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, CaIdentifierRequest.class);
  }

}
