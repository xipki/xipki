// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

import java.time.Instant;

/**
 * Certificate revocation information.
 *
 * @author Lijun Liao (xipki)
 */
public class CertRevocationInfo implements JsonEncodable {

  private CrlReason reason;

  private Instant revocationTime;

  private Instant invalidityTime;

  public CertRevocationInfo(CrlReason reason) {
    this(reason, Instant.now(), null);
  }

  public CertRevocationInfo(CrlReason reason, Instant revocationTime) {
    this(reason, revocationTime, null);
  }

  public CertRevocationInfo(
      CrlReason reason, Instant revocationTime, Instant invalidityTime) {
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

  public CertRevocationInfo(int reasonCode, Instant revocationTime,
                            Instant invalidityTime) {
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
    this.reason = CrlReason.forReasonCode(reasonCode);
    this.invalidityTime = invalidityTime;
  }

  public CrlReason reason() {
    return reason;
  }

  public void setReason(CrlReason reason) {
    this.reason = Args.notNull(reason, "reason");
  }

  public void setRevocationTime(Instant revocationTime) {
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
  }

  public void setInvalidityTime(Instant invalidityTime) {
    this.invalidityTime = invalidityTime;
  }

  /**
   * Gets the revocation time.
   * @return revocation time, never be null
   */
  public Instant revocationTime() {
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
  public String toString() {
    return StringUtil.concatObjects("reason: ", reason,
        "\nrevocationTime: ", revocationTime,
        "\ninvalidityTime: ", invalidityTime);
  }

  public static CertRevocationInfo fromEncoded(String encoded) {
    ConfPairs pairs = new ConfPairs(encoded);
    CrlReason reason = CrlReason.forNameOrText(pairs.value("reason"));
    Instant revocationTime = Instant.ofEpochSecond(
        Long.parseLong(pairs.value("revocationTime")));
    String str = pairs.value("invalidityTime");
    Instant invalidityTime = null;
    if (str != null) {
      invalidityTime = Instant.ofEpochSecond(Long.parseLong(str));
    }

    return new CertRevocationInfo(reason, revocationTime, invalidityTime);
  }

  public String encode() {
    ConfPairs pairs = new ConfPairs()
        .putPair("reason", reason.description())
        .putPair("revocationTime",
            Long.toString(revocationTime.getEpochSecond()));
    if (invalidityTime != null) {
      pairs.putPair("invalidityTime",
          Long.toString(invalidityTime.getEpochSecond()));
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
        && CompareUtil.equals(revocationTime, other.revocationTime)
        && CompareUtil.equals(invalidityTime, other.invalidityTime);
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    if (reason != null) {
      ret.put("reason", reason.description());
    }
    ret.put("revocationTime", revocationTime);
    ret.put("invalidityTime", invalidityTime);
    return ret;
  }

  public static CertRevocationInfo parse(JsonMap json) throws CodecException {
    String str = json.getString("reason");
    CrlReason reason = str == null ? null : CrlReason.forNameOrText(str);
    return new CertRevocationInfo(reason,
        json.getInstant("revocationTime"),
        json.getInstant("invalidityTime"));
  }

}
