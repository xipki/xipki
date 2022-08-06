package org.xipki.ca.sdk;

import java.math.BigInteger;

public class SingleCertSerialEntry {

  /*
   * Uppercase hex encoded serialNumber.
   */
  private BigInteger serialNumber;

  private ErrorEntry error;

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  public ErrorEntry getError() {
    return error;
  }

  public void setError(ErrorEntry error) {
    this.error = error;
  }

}
