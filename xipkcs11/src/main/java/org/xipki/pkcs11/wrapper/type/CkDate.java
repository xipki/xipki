// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.util.codec.Args;

/**
 * Objects of this class represent a CK_DATE.
 * <pre>
 * typedef struct CK_DATE{
 *   CK_CHAR       year[4];   // the year ("1900" - "9999")
 *   CK_CHAR       month[2];  // the month ("01" - "12")
 *   CK_CHAR       day[2];    // the day   ("01" - "31")
 * } CK_DATE;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CkDate extends CkType {

  private final String year;
  private final String month;
  private final String day;

  /**
   * Constructor for internal use only.
   *
   * @param date
   *        the date, of length 8.
   */
  public CkDate(String date) {
    Args.equals(date.length(), "date.length", 8);
    this.year  = date.substring(0, 4);
    this.month = date.substring(4, 6);
    this.day   = date.substring(6, 8);
  }

  public String year() {
    return year;
  }

  public String month() {
    return month;
  }

  public String day() {
    return day;
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return indent + "CK_DATE: " + year + month + day;
  }


  @Override
  public int hashCode() {
    // 961 = 31^2
    return year.hashCode() * 961 + month.hashCode() * 31 + day.hashCode();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    } else if (!(other instanceof CkDate)) {
      return false;
    }

    CkDate b = (CkDate) other;
    return year.equals(b.year) && month.equals(b.month) && day.equals(b.day);
  }

}
