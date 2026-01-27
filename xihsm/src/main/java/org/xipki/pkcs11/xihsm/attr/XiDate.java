// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.attr;

import org.xipki.pkcs11.wrapper.type.CkDate;

/**
 * @author Lijun Liao (xipki)
 */
public class XiDate {

  // yyyymmdd
  private final long date;

  public XiDate(long date) {
    this.date = date;

    long y = date / 10000L;
    long m = date % 10000 / 100L;
    long d = date % 100L;

    boolean valid = (y >= 1900 && y <= 9999)
        && (m >= 1 && m <= 12)
        && (d >= 1 && d <= 31);
    if (!valid) {
      throw new IllegalArgumentException("invalid date: " + date);
    }
  }

  public long getDate() {
    return date;
  }

  public CkDate toCkDate() {
    String s = Long.toString(date);
    return new CkDate(s);
  }

  public static XiDate fromCkDate(CkDate value) {
    return new XiDate(Long.parseLong(
                value.year() + value.month() + value.day()));
  }

}
