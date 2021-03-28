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

package org.xipki.ca.mgmt.db.diffdb;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * Certificate entry containing the serial number, revocation information and hash value of
 * certificates.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class DigestEntry {

  private final BigInteger serialNumber;

  private final boolean revoked;

  private final Integer revReason;

  private final Long revTime;

  private final Long revInvTime;

  private final String base64HashValue;

  public DigestEntry(BigInteger serialNumber, boolean revoked, Integer revReason, Long revTime,
      Long revInvTime, String base64HashValue) {
    Args.notNull(base64HashValue, "base64HashValue");
    if (revoked) {
      Args.notNull(revReason, "revReason");
      Args.notNull(revTime, "revTime");
    }
    this.base64HashValue = base64HashValue;

    this.serialNumber = serialNumber;
    this.revoked = revoked;
    this.revReason = revReason;
    this.revTime = revTime;
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
    if (obj == null) {
      return false;
    }

    if (!serialNumber.equals(obj.serialNumber)) {
      return false;
    }

    if (revoked != obj.revoked) {
      return false;
    }

    if (!equals(revReason, obj.revReason)) {
      return false;
    }

    if (!equals(revTime, obj.revTime)) {
      return false;
    }

    if (!equals(revInvTime, obj.revInvTime)) {
      return false;
    }

    return equals(base64HashValue, obj.base64HashValue);
  } // method contentEquals

  public static DigestEntry decode(String encoded) {
    Args.notNull(encoded, "encoded");

    List<Integer> indexes = getIndexes(encoded);
    if (indexes.size() != 5) {
      throw new IllegalArgumentException("invalid DbDigestEntry: " + encoded);
    }

    String str = encoded.substring(0, indexes.get(0));
    BigInteger serialNumber = new BigInteger(str, 16);

    String sha1Fp = encoded.substring(indexes.get(0) + 1, indexes.get(1));

    int idx = 1;
    str = encoded.substring(indexes.get(idx) + 1, indexes.get(idx + 1));
    boolean revoked = !"0".equals(str);

    Integer revReason = null;
    Long revTime = null;
    Long revInvTime = null;
    if (revoked) {
      idx++;
      str = encoded.substring(indexes.get(idx) + 1, indexes.get(idx + 1));
      revReason = Integer.parseInt(str);

      idx++;
      str = encoded.substring(indexes.get(idx) + 1, indexes.get(idx + 1));
      revTime = Long.parseLong(str);

      idx++;
      str = encoded.substring(indexes.get(idx) + 1);
      if (str.length() != 0) {
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
    return (obj1 == null) ? (obj2 == null) : obj1.equals(obj2);
  }

}
