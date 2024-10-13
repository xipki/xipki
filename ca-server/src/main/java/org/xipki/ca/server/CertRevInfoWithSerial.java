// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.security.CrlReason;
import org.xipki.util.Args;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Certificate revocation information with serial number and database table id.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertRevInfoWithSerial implements Comparable<CertRevInfoWithSerial> {

  private final long id;

  private final BigInteger serial;

  private final CrlReason reason;

  private Instant revocationTime;

  public CertRevInfoWithSerial(long id, BigInteger serial, CrlReason reason,
                               Instant revocationTime) {
    this.reason = Args.notNull(reason, "reason");
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
    this.id = id;
    this.serial = Args.notNull(serial, "serial");
  } // method constructor

  public CertRevInfoWithSerial(long id, BigInteger serial, int reasonCode,
                               Instant revocationTime) {
    this(id, serial, CrlReason.forReasonCode(reasonCode), revocationTime);
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
  public Instant getRevocationTime() {
    if (revocationTime == null) {
      revocationTime = Instant.now();
    }
    return revocationTime;
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
