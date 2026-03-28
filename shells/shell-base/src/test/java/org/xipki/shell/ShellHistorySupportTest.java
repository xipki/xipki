// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for shell history masking.
 *
 * @author Lijun Liao (xipki)
 */
public class ShellHistorySupportTest {

  @Test
  public void testMaskSeparatePasswordValue() {
    String line = "keypair-p12 --password changeit --out output.p12";
    Assert.assertEquals("keypair-p12 --password ******** --out output.p12",
        ShellHistorySupport.maskSensitiveHistoryValues(line));
  }

  @Test
  public void testMaskInlinePinValue() {
    String line = "token-info-p11 --pin=1234";
    Assert.assertEquals("token-info-p11 --pin=****",
        ShellHistorySupport.maskSensitiveHistoryValues(line));
  }

  @Test
  public void testKeepVariableReferenceUnmasked() {
    String line = "keypair-p12 --password ${env:PASSWORD} --out output.p12";
    Assert.assertEquals(line, ShellHistorySupport.maskSensitiveHistoryValues(line));
  }

  @Test
  public void testKeepQuotesWhenMasking() {
    String line = "keypair-p12 --password \"changeit\"";
    Assert.assertEquals("keypair-p12 --password \"********\"",
        ShellHistorySupport.maskSensitiveHistoryValues(line));
  }

}
