// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ChangeCertStatusRequest extends SdkRequest {

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
}
