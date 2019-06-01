/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
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
  }

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
      Instant instant = localDate.atZone(ZONE_UTC).toInstant();
      return Date.from(instant);
    } catch (DateTimeParseException ex) {
      throw new IllegalArgumentException("invalid utcTime '" + utcTime + "': " + ex.getMessage());
    }
  }

  public static String toUtcTimeyyyyMMddhhmmss(Date utcTime) {
    return SDF1.format(utcTime.toInstant().atZone(ZONE_UTC));
  }

  public static String toUtcTimeyyyyMMdd(Date utcTime) {
    return SDF2.format(utcTime.toInstant().atZone(ZONE_UTC));
  }

}
