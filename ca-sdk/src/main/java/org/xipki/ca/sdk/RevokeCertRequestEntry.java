// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.CrlReason;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

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
