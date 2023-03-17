// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Calendar;
import java.util.Date;

/**
 * Utility class for the date conversion.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DateUtil {

  private static final ZoneId ZONE_UTC = ZoneId.of("UTC");

  private static final DateTimeFormatter SDF1 = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

  private static final DateTimeFormatter SDF2 = DateTimeFormatter.ofPattern("yyyyMMdd");

  private DateUtil() {
  }

  public static Date parseUtcTimeyyyyMMddhhmmss(String utcTime) {
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
      Instant instant = localDate.atZone(ZONE_UTC).toInstant();
      return Date.from(instant);
    } catch (DateTimeParseException ex) {
      throw new IllegalArgumentException("invalid utcTime '" + utcTime + "': " + ex.getMessage());
    }
  } // method parseUtcTimeyyyyMMddhhmmss

  public static Date parseUtcTimeyyyyMMdd(String utcTime) {
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
      return Date.from(localDate.atZone(ZONE_UTC).toInstant());
    } catch (DateTimeParseException ex) {
      throw new IllegalArgumentException("invalid utcTime '" + utcTime + "': " + ex.getMessage());
    }
  } // method parseUtcTimeyyyyMMdd

  public static String toUtcTimeyyyyMMddhhmmss(Date utcTime) {
    return SDF1.format(utcTime.toInstant().atZone(ZONE_UTC));
  }

  public static String toUtcTimeyyyyMMdd(Date utcTime) {
    return SDF2.format(utcTime.toInstant().atZone(ZONE_UTC));
  }

  public static long getLastMsOfDay(Calendar cal) {
    cal.set(Calendar.HOUR_OF_DAY, 23);
    cal.set(Calendar.MINUTE, 59);
    cal.set(Calendar.SECOND, 59);
    cal.set(Calendar.MILLISECOND, 999);
    return cal.getTimeInMillis();
  }

  public static int getYyyyMMdd(Calendar cal) {
    return cal.get(Calendar.YEAR) * 10000 + (1 + cal.get(Calendar.MONTH)) * 100 + cal.get(Calendar.DAY_OF_MONTH);
  }

}
