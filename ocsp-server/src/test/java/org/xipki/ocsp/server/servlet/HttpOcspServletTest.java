// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.junit.Assert;
import org.junit.Test;

/**
 * JUnit test case of {@link HttpOcspServlet}.
 * @author Lijun Liao (xipki)
 */
public class HttpOcspServletTest {

  @Test
  public void httpDate() {
    // RFC 9110, section 5.6.7
    Assert.assertEquals("Sun, 06 Nov 1994 08:49:37 GMT", HttpOcspServlet.toHttpDate(784111777L));
    Assert.assertEquals("Thu, 01 Jan 1970 00:00:00 GMT", HttpOcspServlet.toHttpDate(0));
  }

}
