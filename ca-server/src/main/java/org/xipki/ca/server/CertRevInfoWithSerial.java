/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server;

import org.xipki.security.CrlReason;
import org.xipki.util.Args;

import static org.xipki.util.Args.notNull;

import java.math.BigInteger;
import java.util.Date;

/**
 * Certificate revocation information with serial number and database table id.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertRevInfoWithSerial implements Comparable<CertRevInfoWithSerial> {

  private final long id;

  private final BigInteger serial;

  private CrlReason reason;

  private Date revocationTime;

  private Date invalidityTime;

  public CertRevInfoWithSerial(long id, BigInteger serial, CrlReason reason,
      Date revocationTime, Date invalidityTime) {
    this.reason = notNull(reason, "reason");
    this.revocationTime = notNull(revocationTime, "revocationTime");
    this.invalidityTime = invalidityTime;
    this.id = id;
    this.serial = Args.notNull(serial, "serial");
  } // method constructor

  public CertRevInfoWithSerial(long id, BigInteger serial, int reasonCode,
      Date revocationTime, Date invalidityTime) {
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
