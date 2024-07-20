// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.common.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.DateUtil;

import java.time.Instant;

/**
 * JUnit test case of encoding and decoding date time.
 * @author Lijun Liao (xipki)
 */
public class DateTimeParseTest {

  @Test
  public void decodeTimestamp() {
    decodeTimestamp("2016-01-01T08:04:01Z", "2016-01-01T12:04:01+04",
        "2016-01-01T12:04:01+04:00", "2016-01-01T04:04:01-04:00");
    decodeTimestamp("2016-01-01T08:04:01.99Z", "2016-01-01T12:04:01.99+04",
        "2016-01-01T12:04:01.99+04:00", "2016-01-01T04:04:01.99-04:00");
  }

  private static void decodeTimestamp(String timestamp1, String timestamp2, String... timestamps) {
    Instant t1 = DateUtil.parseRFC3339Timestamp(timestamp1);
    Instant t2 = DateUtil.parseRFC3339Timestamp(timestamp2);
    Assert.assertEquals("timestamp", t1, t2);
    if (timestamps != null) {
      for (String timestamp : timestamps) {
        Instant t = DateUtil.parseRFC3339Timestamp(timestamp);
        Assert.assertEquals("timestamp", t1, t);
      }
    }
  }

}
