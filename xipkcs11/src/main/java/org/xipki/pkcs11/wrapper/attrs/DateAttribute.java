// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.type.CkDate;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

/**
 * Objects of this class represent a date attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class DateAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_START_DATE.
   */
  public DateAttribute(long type, Instant value) {
    super(type, toCkDate(value));
  }

  public DateAttribute(long type, CkDate value) {
    super(type, value);
  }

  public void setValue(CkDate value) {
    this.value = value;
  }

  private static CkDate toCkDate(Instant value) {
    if (value == null) {
      return null;
    } else {
      //poor memory/performance behavior, consider alternatives
      ZonedDateTime utcTime = ZonedDateTime.ofInstant(value, ZoneOffset.UTC);
      int year  = utcTime.getYear();
      int month = utcTime.getMonthValue();
      int day   = utcTime.getDayOfMonth();

      String yearT  = Integer.toString(year);
      String monthT = (month < 10 ? "0" + month : Integer.toString(month));
      String dayT   = (  day < 10 ? "0" +   day : Integer.toString(day));
      return new CkDate(yearT + monthT + dayT);
    }
  }

  public CkDate getCkDateValue() {
    if (isNullValue()) {
      return null;
    }

    return (CkDate) value;
  }

  /**
   * Get the date value of this attribute. Null, is also possible.
   *
   * @return The date value of this attribute or null.
   */
  public Instant getValue() {
    if (isNullValue()) {
      return null;
    }

    CkDate ckDate = (CkDate) value;
    int year  = Integer.parseInt(ckDate.year());
    int month = Integer.parseInt(ckDate.month());
    int day   = Integer.parseInt(ckDate.day());
    return ZonedDateTime.of(year, month, day, 0, 0, 0, 0,
        ZoneOffset.UTC).toInstant();
  }

  @Override
  protected String getValueString() {
    if (isNullValue()) {
      return "<NULL_PTR>";
    }

    CkDate ckDate = (CkDate) value;
    return ckDate.year() + "." + ckDate.month() + "." + ckDate.day();
  }

}
