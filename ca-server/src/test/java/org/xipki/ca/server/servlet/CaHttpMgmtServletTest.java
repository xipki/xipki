// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.junit.Assert;
import org.junit.Test;

/**
 * The error message of {@link CaHttpMgmtServlet} in the HTTP header.
 *
 * @author Lijun Liao (xipki)
 */
public class CaHttpMgmtServletTest {

  @Test
  public void controlCharactersAreReplaced() {
    Assert.assertEquals("violation; SQL statement:  DELETE FROM CA WHERE NAME=? ",
        CaHttpMgmtServlet.headerValue("violation; SQL statement:\r\nDELETE FROM CA WHERE NAME=?\n"));
    Assert.assertEquals("a b c", CaHttpMgmtServlet.headerValue("a\tb\u007Fc"));
    Assert.assertEquals("unchanged: äöü", CaHttpMgmtServlet.headerValue("unchanged: äöü"));
    Assert.assertNull(CaHttpMgmtServlet.headerValue(null));
  }

  @Test
  public void lengthIsLimited() {
    Assert.assertEquals(1000, CaHttpMgmtServlet.headerValue("x".repeat(5000)).length());
  }

}
