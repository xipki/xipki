// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

import java.time.Instant;

/**
 * Certificate revocation information.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertRevocationInfo {

  private CrlReason reason;

  private Instant revocationTime;

  private Instant invalidityTime;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CertRevocationInfo() {
  }

  public CertRevocationInfo(CrlReason reason) {
    this(reason, Instant.now(), null);
  }

  public CertRevocationInfo(CrlReason reason, Instant revocationTime) {
    this(reason, revocationTime, null);
  }

  public CertRevocationInfo(CrlReason reason, Instant revocationTime, Instant invalidityTime) {
    this.reason = Args.notNull(reason, "reason");
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
    this.invalidityTime = invalidityTime;
  }

  public CertRevocationInfo(int reasonCode) {
    this(reasonCode, Instant.now(), null);
  }

  public CertRevocationInfo(int reasonCode, Instant revocationTime) {
    this(reasonCode, revocationTime, null);
  }

  public CertRevocationInfo(int reasonCode, Instant revocationTime, Instant invalidityTime) {
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
    this.reason = CrlReason.forReasonCode(reasonCode);
    this.invalidityTime = invalidityTime;
  }

  public void setReason(CrlReason reason) {
    this.reason = Args.notNull(reason, "reason");
  }

  public CrlReason getReason() {
    return reason;
  }

  public void setRevocationTime(Instant revocationTime) {
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
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

  /**
   * Get the invalidity time.
   * @return invalidity time, may be null
   */
  public Instant getInvalidityTime() {
    return invalidityTime;
  }

  public void setInvalidityTime(Instant invalidityTime) {
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
    Instant revocationTime = Instant.ofEpochSecond(Long.parseLong(pairs.value("revocationTime")));
    String str = pairs.value("invalidityTime");
    Instant invalidityTime = null;
    if (str != null) {
      invalidityTime = Instant.ofEpochSecond(Long.parseLong(pairs.value("invalidityTime")));
    }

    return new CertRevocationInfo(reason, revocationTime, invalidityTime);
  }

  public String encode() {
    ConfPairs pairs = new ConfPairs()
        .putPair("reason", reason.getDescription())
        .putPair("revocationTime", Long.toString(revocationTime.getEpochSecond()));
    if (invalidityTime != null) {
      pairs.putPair("invalidityTime", Long.toString(invalidityTime.getEpochSecond()));
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
