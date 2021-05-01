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

package org.xipki.security;

import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

import java.util.Date;

import static org.xipki.util.Args.notNull;

/**
 * Certificate revocation information.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertRevocationInfo {

  private CrlReason reason;

  private Date revocationTime;

  private Date invalidityTime;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CertRevocationInfo() {
  }

  public CertRevocationInfo(CrlReason reason) {
    this(reason, new Date(), null);
  }

  public CertRevocationInfo(CrlReason reason, Date revocationTime) {
    this(reason, revocationTime, null);
  }

  public CertRevocationInfo(CrlReason reason, Date revocationTime, Date invalidityTime) {
    this.reason = notNull(reason, "reason");
    this.revocationTime = notNull(revocationTime, "revocationTime");
    this.invalidityTime = invalidityTime;
  }

  public CertRevocationInfo(int reasonCode) {
    this(reasonCode, new Date(), null);
  }

  public CertRevocationInfo(int reasonCode, Date revocationTime) {
    this(reasonCode, revocationTime, null);
  }

  public CertRevocationInfo(int reasonCode, Date revocationTime, Date invalidityTime) {
    this.revocationTime = notNull(revocationTime, "revocationTime");
    this.reason = CrlReason.forReasonCode(reasonCode);
    this.invalidityTime = invalidityTime;
  }

  public void setReason(CrlReason reason) {
    this.reason = notNull(reason, "reason");
  }

  public CrlReason getReason() {
    return reason;
  }

  public void setRevocationTime(Date revocationTime) {
    this.revocationTime = notNull(revocationTime, "revocationTime");
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

  public void setInvalidityTime(Date invalidityTime) {
    this.invalidityTime = invalidityTime;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects("reason: ", reason, "\nrevocationTime: ", revocationTime,
        "\ninvalidityTime: ", invalidityTime);
  }

  public static CertRevocationInfo fromEncoded(String encoded) {
    ConfPairs pairs = new ConfPairs(encoded);
    CrlReason reason = CrlReason.forNameOrText(pairs.value("reason"));
    Date revocationTime = new Date(1000L * Long.parseLong(pairs.value("revocationTime")));
    String str = pairs.value("invalidityTime");
    Date invalidityTime = null;
    if (str != null) {
      invalidityTime = new Date(1000L * Long.parseLong(pairs.value("invalidityTime")));
    }

    return new CertRevocationInfo(reason, revocationTime, invalidityTime);
  }

  public String getEncoded() {
    ConfPairs pairs = new ConfPairs();
    pairs.putPair("reason", reason.getDescription());
    pairs.putPair("revocationTime", Long.toString(revocationTime.getTime() / 1000));
    if (invalidityTime != null) {
      pairs.putPair("invalidityTime", Long.toString(invalidityTime.getTime() / 1000));
    }
    return pairs.getEncoded();
  }

  @Override
  public int hashCode() {
    return reason.hashCode() + 31 * revocationTime.hashCode()
            + (invalidityTime == null ? 0 : 31 * 31 * invalidityTime.hashCode());
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }

    if (!(obj instanceof CertRevocationInfo)) {
      return false;
    }

    CertRevocationInfo other = (CertRevocationInfo) obj;
    return reason == other.reason
        && CompareUtil.equalsObject(revocationTime, other.revocationTime)
        && CompareUtil.equalsObject(invalidityTime, other.invalidityTime);
  }

}
