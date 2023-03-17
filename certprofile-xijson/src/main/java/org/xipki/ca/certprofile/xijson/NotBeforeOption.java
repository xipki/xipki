// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.util.Args;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * Control of the certificate's NotBefore field.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public class NotBeforeOption {

  private final TimeZone midNightTimeZone;

  private final Long offsetMillis;

  private NotBeforeOption(TimeZone midNightTimeZone, Long offsetSeconds) {
    this.midNightTimeZone = midNightTimeZone;
    this.offsetMillis = (offsetSeconds == null) ? null : offsetSeconds * 1000;
  }

  static NotBeforeOption getMidNightOption(TimeZone timeZone) {
    return new NotBeforeOption(timeZone, null);
  }

  static NotBeforeOption getOffsetOption(long offsetSeconds) {
    Args.min(offsetSeconds, "offsetSeconds", -600);
    return new NotBeforeOption(null, offsetSeconds);
  }

  Date getNotBefore(Date requestedNotBefore) {
    long now = System.currentTimeMillis();
    if (requestedNotBefore != null) {
      long notOlderThan = (offsetMillis != null && offsetMillis < 0) ? now + offsetMillis : now;
      long notBefore = Math.max(requestedNotBefore.getTime(), notOlderThan);

      return (midNightTimeZone == null) ? new Date(notBefore) : setToMidnight(notBefore);
    } else {
      return (midNightTimeZone != null) ? setToMidnight(now) : new Date(System.currentTimeMillis() + offsetMillis);
    }
  } // method getNotBefore

  private Date setToMidnight(long date) {
    Calendar cal = Calendar.getInstance(midNightTimeZone);
    // the next midnight time
    final long dayInMs = 24L * 60 * 60 * 1000;
    cal.setTime(new Date(date + dayInMs - 1));
    cal.set(Calendar.HOUR_OF_DAY, 0);
    cal.set(Calendar.MINUTE, 0);
    cal.set(Calendar.SECOND, 0);
    cal.set(Calendar.MILLISECOND, 0);
    return cal.getTime();
  } // method setToMidnight

  public TimeZone getMidNightTimeZone() {
    return midNightTimeZone;
  }

  public Long getOffsetMillis() {
    return offsetMillis;
  }

}
