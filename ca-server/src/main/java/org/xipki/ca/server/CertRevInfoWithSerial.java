// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.security.pkix.CrlReason;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Certificate revocation information with serial number and database table id.
 *
 * @author Lijun Liao (xipki)
 */

public class CertRevInfoWithSerial
    implements Comparable<CertRevInfoWithSerial> {

  private final long id;

  private final BigInteger serial;

  private final CrlReason reason;

  private Instant revocationTime;

  private final Instant invalidityTime;

  public CertRevInfoWithSerial(long id, BigInteger serial, CrlReason reason,
                               Instant revocationTime, Instant invalidityTime) {
    this.reason = Args.notNull(reason, "reason");
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
    this.invalidityTime = invalidityTime;
    this.id = id;
    this.serial = Args.notNull(serial, "serial");
  } // method constructor

  public CertRevInfoWithSerial(long id, BigInteger serial, int reasonCode,
                               Instant revocationTime, Instant invalidityTime) {
    this(id, serial, CrlReason.forReasonCode(reasonCode), revocationTime,
        invalidityTime);
  } // method constructor

  public BigInteger serial() {
    return serial;
  }

  public long id() {
    return id;
  }

  public CrlReason reason() {
    return reason;
  }

  /**
   * Gets the revocation time.
   * @return revocation time, never be null
   */
  public Instant revocationTime() {
    if (revocationTime == null) {
      revocationTime = Instant.now();
    }
    return revocationTime;
  }

  /**
   * Get the invalidity time.
   * @return invalidity time, may be null
   */
  public Instant invalidityTime() {
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
