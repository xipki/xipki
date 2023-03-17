// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.security.CrlReason;
import org.xipki.util.Args;

import java.math.BigInteger;
import java.util.Date;

import static org.xipki.util.Args.notNull;

/**
 * Certificate revocation information with serial number and database table id.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertRevInfoWithSerial implements Comparable<CertRevInfoWithSerial> {

  private final long id;

  private final BigInteger serial;

  private final CrlReason reason;

  private Date revocationTime;

  private final Date invalidityTime;

  public CertRevInfoWithSerial(long id, BigInteger serial, CrlReason reason, Date revocationTime, Date invalidityTime) {
    this.reason = notNull(reason, "reason");
    this.revocationTime = notNull(revocationTime, "revocationTime");
    this.invalidityTime = invalidityTime;
    this.id = id;
    this.serial = Args.notNull(serial, "serial");
  } // method constructor

  public CertRevInfoWithSerial(long id, BigInteger serial, int reasonCode, Date revocationTime, Date invalidityTime) {
    this(id, serial, CrlReason.forReasonCode(reasonCode), revocationTime, invalidityTime);
  } // method constructor

  public BigInteger getSerial() {
    return serial;
  }

  public long getId() {
    return id;
  }

  public CrlReason getReason() {
    return reason;
  }

  /**
   * Gets the revocation time.
   * @return revocation time, never be null
   */
  public Date getRevocationTime() {
    if (revocationTime == null) {
      revocationTime = new Date();
    }
    return revocationTime;
  }

  /**
   * Get the invalidity time.
   * @return invalidity time, may be null
   */
  public Date getInvalidityTime() {
    return invalidityTime;
  }

  @Override
  public int compareTo(CertRevInfoWithSerial other) {
    return serial.compareTo(other.serial);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof CertRevInfoWithSerial)) {
      return false;
    }

    CertRevInfoWithSerial o = (CertRevInfoWithSerial) obj;
    return id == o.id && serial.equals(o.serial);
  }

  @Override
  public int hashCode() {
    return serial.intValue() + 37 * (int) id;
  }

}
