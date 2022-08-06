package org.xipki.ca.sdk;

import org.xipki.security.CrlReason;

import java.math.BigInteger;

public class RevokeCertRequestEntry {

  /*
   * Uppercase hex encoded serialNumber.
   */
  private BigInteger serialNumber;

  private CrlReason reason;

  /**
   * Epoch time in seconds of invalidity time.
   */
  private Long invalidityTime;

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  public CrlReason getReason() {
    return reason;
  }

  public void setReason(CrlReason reason) {
    this.reason = reason;
  }

  public Long getInvalidityTime() {
    return invalidityTime;
  }

  public void setInvalidityTime(Long invalidityTime) {
    this.invalidityTime = invalidityTime;
  }
}
