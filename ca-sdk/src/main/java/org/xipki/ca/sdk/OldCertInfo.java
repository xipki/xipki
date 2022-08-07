package org.xipki.ca.sdk;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class OldCertInfo {

  /**
   * Whether to reu-use the public key in the old certificate for the new one.
   */
  private boolean reusePublicKey;

  private X500NameType issuer;

  /**
   * Uppercase hex encoded serialNumber.
   */
  private BigInteger serialNumber;

  public X500NameType getIssuer() {
    return issuer;
  }

  public void setIssuer(X500NameType issuer) {
    this.issuer = issuer;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  public boolean isReusePublicKey() {
    return reusePublicKey;
  }

  public void setReusePublicKey(boolean reusePublicKey) {
    this.reusePublicKey = reusePublicKey;
  }
}
