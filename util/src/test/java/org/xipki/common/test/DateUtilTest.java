// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.common.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.DateUtil;

import java.time.Instant;

/**
 * Test for {@link DateUtil}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class DateUtilTest {

  @Test
  public void test1() {
    Instant utcDate = DateUtil.parseUtcTimeyyyyMMddhhmmss("20150223134459");
    long expTimeSeconds = 1424699099L;

    Assert.assertEquals("DateTime parsing", expTimeSeconds, utcDate.getEpochSecond());
  }
}
