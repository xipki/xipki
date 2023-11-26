// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Certificate entry containing the serial number, revocation information and hash value of
 * certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class DigestEntry {

  private final BigInteger serialNumber;

  private final boolean revoked;

  private final Integer revReason;

  private final Long revTime;

  private final Long revInvTime;

  private final String base64HashValue;

  public DigestEntry(BigInteger serialNumber, boolean revoked, Integer revReason,
                     Long revTime, Long revInvTime, String base64HashValue) {
    this.base64HashValue = Args.notNull(base64HashValue, "base64HashValue");
    this.serialNumber = serialNumber;
    this.revoked = revoked;
    this.revReason = revoked ? Args.notNull(revReason, "revReason") : null;
    this.revTime = revoked ? Args.notNull(revTime, "revTime") : null;
    this.revInvTime = revInvTime;
  } // constructor

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public boolean isRevoked() {
    return revoked;
  }

  public int getRevReason() {
    return revReason;
  }

  public Long getRevTime() {
    return revTime;
  }

  public Long getRevInvTime() {
    return revInvTime;
  }

  public String getBase64HashValue() {
    return base64HashValue;
  }

  @Override
  public String toString() {
    return encoded();
  }

  public String encodedOmitSeriaNumber() {
    return encoded(false);
  }

  public String encoded() {
    return encoded(true);
  }

  private String encoded(boolean withSerialNumber) {
    return StringUtil.concatObjects((withSerialNumber ? serialNumber.toString(16) + ";" : ""),
        base64HashValue, ";", (revoked ? "1" : "0"), ";", (revReason != null ? revReason : ""), ";",
        (revTime != null ? revTime : ""), ";", (revInvTime != null ? revInvTime : ""));
  }

  public boolean contentEquals(DigestEntry obj) {
    return obj != null && serialNumber.equals(obj.serialNumber) && (revoked == obj.revoked)
        && equals(revReason,  obj.revReason)  && equals(revTime, obj.revTime)
        && equals(revInvTime, obj.revInvTime) && equals(base64HashValue, obj.base64HashValue);
  } // method contentEquals

  public static DigestEntry decode(String encoded) {
    List<Integer> indexes = getIndexes(Args.notNull(encoded, "encoded"));
    if (indexes.size() != 5) {
      throw new IllegalArgumentException("invalid DbDigestEntry: " + encoded);
    }

    int idx = 0;
    String str = encoded.substring(0, indexes.get(idx));
    BigInteger serialNumber = new BigInteger(str, 16);

    String sha1Fp = encoded.substring(indexes.get(idx) + 1, indexes.get(++idx));

    str = encoded.substring(indexes.get(idx) + 1, indexes.get(++idx));
    boolean revoked = !"0".equals(str);

    Integer revReason = null;
    Long revTime = null;
    Long revInvTime = null;
    if (revoked) {
      str = encoded.substring(indexes.get(idx) + 1, indexes.get(++idx));
      revReason = Integer.parseInt(str);

      str = encoded.substring(indexes.get(idx) + 1, indexes.get(++idx));
      revTime = Long.parseLong(str);

      str = encoded.substring(indexes.get(idx) + 1);
      if (!str.isEmpty()) {
        revInvTime = Long.parseLong(str);
      }
    }

    return new DigestEntry(serialNumber, revoked, revReason, revTime, revInvTime, sha1Fp);
  } // method decode

  private static List<Integer> getIndexes(String encoded) {
    List<Integer> ret = new ArrayList<>(6);
    for (int i = 0; i < encoded.length(); i++) {
      if (encoded.charAt(i) == ';') {
        ret.add(i);
      }
    }
    return ret;
  } // method getIndexes

  private static boolean equals(Object obj1, Object obj2) {
    return Objects.equals(obj1, obj2);
  }

}
