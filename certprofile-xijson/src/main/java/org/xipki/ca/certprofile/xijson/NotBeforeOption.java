// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.util.codec.Args;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;

/**
 * Control of the certificate's NotBefore field.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class NotBeforeOption {

  private final ZoneId midNightTimeZone;

  private final Long offsetSeconds;

  private NotBeforeOption(ZoneId midNightTimeZone, Long offsetSeconds) {
    this.midNightTimeZone = midNightTimeZone;
    this.offsetSeconds = offsetSeconds;
  }

  static NotBeforeOption getMidNightOption(ZoneId timeZone) {
    return new NotBeforeOption(timeZone, null);
  }

  static NotBeforeOption getOffsetOption(long offsetSeconds) {
    Args.min(offsetSeconds, "offsetSeconds", -600);
    return new NotBeforeOption(null, offsetSeconds);
  }

  Instant getNotBefore(Instant requestedNotBefore) {
    Instant now = Instant.now();
    long nowSecond = now.getEpochSecond();
    if (requestedNotBefore != null) {
      long notOlderThan = (offsetSeconds != null && offsetSeconds < 0)
          ? nowSecond + offsetSeconds : nowSecond;
      long notBefore = Math.max(requestedNotBefore.getEpochSecond(),
          notOlderThan);
      return (midNightTimeZone != null) ? setToMidnight(notBefore) : now;
    } else {
      return (midNightTimeZone != null) ? setToMidnight(nowSecond)
          : now.plusSeconds(offsetSeconds);
    }
  } // method getNotBefore

  // get the next mid-night time.
  private Instant setToMidnight(long epochSeconds) {
    ZonedDateTime zd = ZonedDateTime.ofInstant(
        Instant.ofEpochSecond(epochSeconds).plus(1, ChronoUnit.DAYS)
            .minus(1, ChronoUnit.MILLIS),
        midNightTimeZone);

    return ZonedDateTime.of(zd.getYear(), zd.getMonthValue(),
        zd.getDayOfMonth(), 0, 0, 0, 0,
        midNightTimeZone)
        .toInstant();
  } // method setToMidnight

  public ZoneId getMidNightTimeZone() {
    return midNightTimeZone;
  }

  public Long getOffsetSeconds() {
    return offsetSeconds;
  }

}
