// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Date;

/**
 * Utility class for the date conversion.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class DateUtil {

  private static final ZoneId ZONE_UTC = ZoneId.of("UTC");

  private static final DateTimeFormatter SDF1 = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

  private static final DateTimeFormatter SDF2 = DateTimeFormatter.ofPattern("yyyyMMdd");

  private DateUtil() {
  }

  public static Instant parseUtcTimeyyyyMMddhhmmss(String utcTime) {
    String coreUtcTime = utcTime;
    if (StringUtil.isNotBlank(utcTime)) {
      char ch = utcTime.charAt(utcTime.length() - 1);
      if (ch == 'z' || ch == 'Z') {
        coreUtcTime = utcTime.substring(0, utcTime.length() - 1);
      }
    }

    if (coreUtcTime == null || coreUtcTime.length() != 14) {
      throw new IllegalArgumentException("invalid utcTime '" + utcTime + "'");
    }

    try {
      LocalDateTime localDate = LocalDateTime.parse(coreUtcTime, SDF1);
      return localDate.atZone(ZONE_UTC).toInstant();
    } catch (DateTimeParseException ex) {
      throw new IllegalArgumentException("invalid utcTime '" + utcTime + "': " + ex.getMessage());
    }
  } // method parseUtcTimeyyyyMMddhhmmss

  public static Instant parseUtcTimeyyyyMMdd(String utcTime) {
    String coreUtcTime = utcTime;
    if (StringUtil.isNotBlank(utcTime)) {
      char ch = utcTime.charAt(utcTime.length() - 1);
      if (ch == 'z' || ch == 'Z') {
        coreUtcTime = utcTime.substring(0, utcTime.length() - 1);
      }
    }

    if (coreUtcTime == null || coreUtcTime.length() != 8) {
      throw new IllegalArgumentException("invalid utcTime '" + utcTime + "'");
    }

    try {
      LocalDateTime localDate = LocalDateTime.parse(coreUtcTime + "000000", SDF1);
      return localDate.atZone(ZONE_UTC).toInstant();
    } catch (DateTimeParseException ex) {
      throw new IllegalArgumentException("invalid utcTime '" + utcTime + "': " + ex.getMessage());
    }
  } // method parseUtcTimeyyyyMMdd

  public static String toUtcTimeyyyyMMddhhmmss(Instant time) {
    return SDF1.format(time.atZone(ZONE_UTC));
  }

  public static String toUtcTimeyyyyMMdd(Instant time) {
    return SDF2.format(time.atZone(ZONE_UTC));
  }

  public static Instant getLastMsOfDay(ZonedDateTime cal) {
    return ZonedDateTime.of(cal.getYear(), cal.getMonthValue(), cal.getDayOfMonth(),
        23, 59, 59, 999, cal.getZone()).toInstant();
  }

  public static int getYyyyMMdd(ZonedDateTime cal) {
    return cal.getYear() * 10000 + cal.getMonthValue() * 100 + cal.getDayOfMonth();
  }

  public static long toEpochSecond(Date date) {
    return date.getTime() / 1000;
  }

}
