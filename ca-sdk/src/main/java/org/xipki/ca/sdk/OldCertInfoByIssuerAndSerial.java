package org.xipki.ca.sdk;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class OldCertInfoByIssuerAndSerial extends OldCertInfo {

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

}
