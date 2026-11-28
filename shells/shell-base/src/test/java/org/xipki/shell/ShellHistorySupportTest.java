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
        ShellHistorySupport.maskSensitiveValues(line));
  }

  @Test
  public void testMaskInlinePinValue() {
    String line = "token-info-p11 --pin=1234";
    Assert.assertEquals("token-info-p11 --pin=****",
        ShellHistorySupport.maskSensitiveValues(line));
  }

  @Test
  public void testKeepVariableReferenceUnmasked() {
    String line = "keypair-p12 --password ${env:PASSWORD} --out output.p12";
    Assert.assertEquals(line, ShellHistorySupport.maskSensitiveValues(line));
  }

  @Test
  public void testKeepQuotesWhenMasking() {
    String line = "keypair-p12 --password \"changeit\"";
    Assert.assertEquals("keypair-p12 --password \"********\"",
        ShellHistorySupport.maskSensitiveValues(line));
  }

  @Test
  public void testMaskOtherPasswordOptions() {
    String line = "cmp-enroll --signer-password changeit-cmpclient --inpwd=1234 --outpwd 5678";
    Assert.assertEquals("cmp-enroll --signer-password ******************"
        + " --inpwd=**** --outpwd ****",
        ShellHistorySupport.maskSensitiveValues(line));
  }

  @Test
  public void testKeepPasswordFileUnmasked() {
    String line = "keypair-p12 --password-file pwd.txt --out output.p12";
    Assert.assertEquals(line, ShellHistorySupport.maskSensitiveValues(line));
  }

  @Test
  public void testMaskPasswordInConfString() {
    String line = "ca-add --signer-conf \"algo=ECDSA-SHA256,password=CHANGEIT,keystore=file:ca.p12\""
        + " --conf password=1234";
    Assert.assertEquals("ca-add --signer-conf \"algo=ECDSA-SHA256,password=********,"
        + "keystore=file:ca.p12\" --conf password=****",
        ShellHistorySupport.maskSensitiveValues(line));
  }

  @Test
  public void testKeepVariableInConfStringUnmasked() {
    String line = "ca-add --signer-conf \"password=${CA_P12_PWD},keystore=file:ca.p12\"";
    Assert.assertEquals(line, ShellHistorySupport.maskSensitiveValues(line));
  }

}
