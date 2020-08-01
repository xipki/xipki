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

package org.xipki.util;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * Validity like the certificate validity, e.g. 3 years.
 *
 * @author Lijun Liao
 */

public class Validity implements Comparable<Validity> {

  public enum Unit {

    YEAR("y"),
    WEEK("w"),
    DAY("d"),
    HOUR("h"),
    MINUTE("m");

    private String suffix;

    private Unit(String suffix) {
      this.suffix = suffix;
    }

    public String getSuffix() {
      return suffix;
    }

  } // class Unit

  private static final long MINUTE = 60L * 1000;

  private static final long HOUR = 60L * MINUTE;

  private static final long DAY = 24L * HOUR;

  private static final long WEEK = 7L * DAY;

  private static final TimeZone TIMEZONE_UTC = TimeZone.getTimeZone("UTC");

  private int validity;
  private Unit unit;

  // For the deserialization only
  @SuppressWarnings("unused")
  private Validity() {
  }

  public Validity(int validity, Unit unit) {
    this.validity = positive(validity, "validity");
    this.unit = notNull(unit, "unit");
  }

  public static Validity getInstance(String validityS) {
    notBlank(validityS, "validityS");

    final int len = validityS.length();
    final char suffix = validityS.charAt(len - 1);
    Unit unit;
    String numValdityS;
    if (suffix == 'y' || suffix == 'Y') {
      unit = Unit.YEAR;
      numValdityS = validityS.substring(0, len - 1);
    } else if (suffix == 'w' || suffix == 'W') {
      unit = Unit.WEEK;
      numValdityS = validityS.substring(0, len - 1);
    } else if (suffix == 'd' || suffix == 'D') {
      unit = Unit.DAY;
      numValdityS = validityS.substring(0, len - 1);
    } else if (suffix == 'h' || suffix == 'H') {
      unit = Unit.HOUR;
      numValdityS = validityS.substring(0, len - 1);
    } else if (suffix == 'm' || suffix == 'M') {
      unit = Unit.MINUTE;
      numValdityS = validityS.substring(0, len - 1);
    } else if (suffix >= '0' && suffix <= '9') {
      unit = Unit.DAY;
      numValdityS = validityS;
    } else {
      throw new IllegalArgumentException(String.format("invalid validityS: %s", validityS));
    }

    int validity;
    try {
      validity = Integer.parseInt(numValdityS);
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException(String.format("invalid validityS: %s", validityS));
    }
    return new Validity(validity, unit);
  } // method getInstance

  public void setValidity(int validity) {
    this.validity = positive(validity, "validity");
  }

  public int getValidity() {
    return validity;
  }

  public void setUnit(Unit unit) {
    this.unit = notNull(unit, "unit");
  }

  public Unit getUnit() {
    return unit;
  }

  public Date add(Date referenceDate) {
    switch (unit) {
      case YEAR:
        Calendar cal = Calendar.getInstance(TIMEZONE_UTC);
        cal.setTime(referenceDate);
        cal.add(Calendar.YEAR, validity);

        int month = cal.get(Calendar.MONTH);
        // February
        if (month == 1) {
          int day = cal.get(Calendar.DAY_OF_MONTH);
          if (day > 28) {
            int year = cal.get(Calendar.YEAR);
            day = isLeapYear(year) ? 29 : 28;
          }
        }

        return cal.getTime();
      case WEEK:
        return new Date(referenceDate.getTime() + validity * WEEK);
      case DAY:
        return new Date(referenceDate.getTime() + validity * DAY);
      case HOUR:
        return new Date(referenceDate.getTime() + validity * HOUR);
      case MINUTE:
        return new Date(referenceDate.getTime() + validity * MINUTE);
      default:
        throw new IllegalStateException(String.format(
            "should not reach here, unknown Validity.Unit %s", unit));
    }
  } // method add

  public long approxMinutes() {
    switch (unit) {
      case YEAR:
        return (365L * 24 * validity + 6 * validity) * 60;
      case WEEK:
        return 7L * 24 * 60 * validity;
      case DAY:
        return 24L * 60 * validity;
      case HOUR:
        return 60L * validity;
      case MINUTE:
        return validity;
      default:
        throw new IllegalStateException(String.format(
            "should not reach here, unknown Validity.Unit %s", unit));
    }
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public int compareTo(Validity obj) {
    notNull(obj, "obj");
    if (unit == obj.unit) {
      if (validity == obj.validity) {
        return 0;
      }

      return (validity < obj.validity) ? -1 : 1;
    } else {
      long thisMinutes = approxMinutes();
      long thatMinutes = obj.approxMinutes();
      if (thisMinutes == thatMinutes) {
        return 0;
      } else {
        return (thisMinutes < thatMinutes) ? -1 : 1;
      }
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof Validity)) {
      return false;
    }

    Validity other = (Validity) obj;
    return unit == other.unit && validity == other.validity;
  }

  @Override
  public String toString() {
    switch (unit) {
      case YEAR:
        return validity + "y";
      case WEEK:
        return validity + "w";
      case DAY:
        return validity + "d";
      case HOUR:
        return validity + "h";
      case MINUTE:
        return validity + "m";
      default:
        throw new IllegalStateException(String.format(
            "should not reach here, unknown Validity.Unit %s", unit));
    }
  }

  private static boolean isLeapYear(int year) {
    if (year % 4 != 0) {
      return false;
    } else if (year % 100 != 0) {
      return true;
    } else {
      return year % 400 == 0;
    }
  }

}
