// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class PollCertRequest extends SdkRequest {

  private String transactionId;

  /**
   * SHA-1 fingerprint of the DER-encoded issuer's certificate
   */
  private byte[] issuerCertSha1Fp;

  private X500NameType issuer;

  private byte[] authorityKeyIdentifier;

  private List<PollCertRequestEntry> entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

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

  public List<PollCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<PollCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static PollCertRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, PollCertRequest.class);
  }

}
