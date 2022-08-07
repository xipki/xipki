package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ChangeCertStatusRequest extends SdkRequest {

  /**
   * Hash algorithm to compute {@link #issuerFp}. Optional.
   */
  private String issuerFpAlgo;

  /**
   * Fingerprint of the DER-encoded issuer's certificate
   */
  private byte[] issuerFp;

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

  public String getIssuerFpAlgo() {
    return issuerFpAlgo;
  }

  public void setIssuerFpAlgo(String issuerFpAlgo) {
    this.issuerFpAlgo = issuerFpAlgo;
  }

  public byte[] getIssuerFp() {
    return issuerFp;
  }

  public void setIssuerFp(byte[] issuerFp) {
    this.issuerFp = issuerFp;
  }

}
