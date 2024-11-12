// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
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

  public static Instant parseRFC3339Timestamp(String timestamp) throws DateTimeParseException {
    if (timestamp.endsWith("Z")) {
      return Instant.parse(timestamp);
    } else {
      // This block can be deleted for JDK-17
      // e.g. 2016-01-01T01:04:01+04:00, and 2016-01-01T01:04:01.99+04:00
      boolean plusOffset = true;
      int signIndex = timestamp.lastIndexOf('+');
      if (signIndex == -1) {
        plusOffset = false;
        signIndex = timestamp.lastIndexOf('-');
      }
      if (signIndex < 19) {
        throw new DateTimeParseException("invalid timestamp", timestamp, 0);
      }

      String timePart = timestamp.substring(0, signIndex);
      Instant time = Instant.parse(timePart + "Z");
      String offPart = timestamp.substring(signIndex + 1);
      String[] offTokens = offPart.substring(1).split(":");
      int offHour = Integer.parseInt(offTokens[0]);
      int offMin = 0;
      if (offTokens.length > 1) {
        offMin = Integer.parseInt(offTokens[1]);
      }

      int offMinutes = offHour * 60 + offMin;
      if (plusOffset) {
        offMinutes *= -1;
      }
      return time.plus(offMinutes, ChronoUnit.MINUTES);
    }
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
