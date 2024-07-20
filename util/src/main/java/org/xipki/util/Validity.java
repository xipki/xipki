// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;

/**
 * Validity like the certificate validity, e.g. 3 years.
 *
 * @author Lijun Liao (xipki)
 */

public class Validity implements Comparable<Validity> {

  public enum Unit {

    YEAR("y", ChronoUnit.YEARS),
    WEEK("w", ChronoUnit.WEEKS),
    DAY("d", ChronoUnit.DAYS),
    HOUR("h", ChronoUnit.HOURS),
    MINUTE("m", ChronoUnit.MINUTES);

    private final String suffix;

    private final ChronoUnit unit;

    Unit(String suffix, ChronoUnit unit) {
      this.suffix = suffix;
      this.unit = unit;
    }

    public String getSuffix() {
      return suffix;
    }

    public ChronoUnit getUnit() {
      return unit;
    }

  } // class Unit

  private static final ZoneId TIMEZONE_UTC = ZoneId.of("UTC");

  private final int validity;
  private final Unit unit;

  // For the deserialization only
  @SuppressWarnings("unused")
  public Validity(int validity, Unit unit) {
    this.validity = Args.positive(validity, "validity");
    this.unit = Args.notNull(unit, "unit");
  }

  public static Validity getInstance(String validityS) {
    final int len = Args.notBlank(validityS, "validityS").length();
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

    try {
      return new Validity(Integer.parseInt(numValdityS), unit);
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException(String.format("invalid validityS: %s", validityS));
    }
  } // method getInstance

  public int getValidity() {
    return validity;
  }

  public Unit getUnit() {
    return unit;
  }

  public Instant add(Instant referenceDate) {
    if (unit == Unit.YEAR) {
      ZonedDateTime utcDate = referenceDate.atZone(TIMEZONE_UTC);
      int year = utcDate.getYear();
      int month = utcDate.getMonthValue();
      int day = utcDate.getDayOfMonth();
      if (month == 2 && day == 29) {
        if (!isLeapYear(validity + year)) {
          day = 28;
        }
      }
      return ZonedDateTime.of(year + validity, month, day, utcDate.getHour(), utcDate.getMinute(),
          utcDate.getSecond(), 0, TIMEZONE_UTC).toInstant();
    } else {
      return referenceDate.plus(validity, unit.getUnit());
    }
  } // method add

  public long approxMinutes() {
    return unit.getUnit().getDuration().getSeconds() / 60;
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public int compareTo(Validity obj) {
    if (unit == Args.notNull(obj, "obj").unit) {
      if (validity == obj.validity) {
        return 0;
      }

      return (validity < obj.validity) ? -1 : 1;
    } else {
      return Long.compare(approxMinutes(), obj.approxMinutes());
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
        throw new IllegalStateException(String.format("should not reach here, unknown Validity.Unit %s", unit));
    }
  }

  private static boolean isLeapYear(int year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  }

}
