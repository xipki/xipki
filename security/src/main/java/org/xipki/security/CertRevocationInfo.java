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

  // For the deserialization only
  @SuppressWarnings("unused")
  private CertRevocationInfo() {
  }

  public CertRevocationInfo(CrlReason reason) {
    this(reason, Instant.now());
  }

  public CertRevocationInfo(CrlReason reason, Instant revocationTime) {
    this.reason = Args.notNull(reason, "reason");
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
  }

  public CertRevocationInfo(int reasonCode) {
    this(reasonCode, Instant.now());
  }

  public CertRevocationInfo(int reasonCode, Instant revocationTime) {
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
    this.reason = CrlReason.forReasonCode(reasonCode);
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

  @Override
  public String toString() {
    return StringUtil.concatObjects("reason: ", reason, "\nrevocationTime: ", revocationTime);
  }

  public static CertRevocationInfo fromEncoded(String encoded) {
    ConfPairs pairs = new ConfPairs(encoded);
    CrlReason reason = CrlReason.forNameOrText(pairs.value("reason"));
    Instant revocationTime = Instant.ofEpochSecond(Long.parseLong(pairs.value("revocationTime")));

    return new CertRevocationInfo(reason, revocationTime);
  }

  public String encode() {
    ConfPairs pairs = new ConfPairs()
        .putPair("reason", reason.getDescription())
        .putPair("revocationTime", Long.toString(revocationTime.getEpochSecond()));
    return pairs.getEncoded();
  }

  @Override
  public int hashCode() {
    return reason.hashCode() + 31 * revocationTime.hashCode();
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
        && CompareUtil.equalsObject(revocationTime, other.revocationTime);
  }

}
