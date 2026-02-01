// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.keygeneration;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_GENERATE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_AES;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_AES_KEY_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.ckmCodeToName;

/**
 * AES speed test base class.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class AESKeyGenSpeedTest extends TestBase {

  private class MyExecutor extends KeyGenExecutor {

    public MyExecutor(boolean inToken) {
      super(mechanism, getKeyByteLen(), inToken);
    }

    @Override
    protected PKCS11SecretKeySpec getMinimalKeyTemplate() {
      return newSecretKey(CKK_AES).valueLen(getKeyByteLen());
    }

  }

  private static final long mechanism = CKM_AES_KEY_GEN;

  protected abstract int getKeyByteLen();

  @Override
  protected TestHSMs.TestHSM getHSM() {
    return TestHSMs.getHsmForSpeed();
  }

  @Test
  public void execTest() {
    PKCS11Token token = getToken();

    Assume.assumeTrue(ckmCodeToName(mechanism) +
            " is not supported, skip test",
        token.supportsMechanism(mechanism, CKF_GENERATE));

    boolean[] inTokens = new boolean[] {false, true};
    for (boolean inToken : inTokens) {
      MyExecutor executor = new MyExecutor(inToken);
      executor.setThreads(TestHSMs.getSpeedThreads());
      executor.setDuration(TestHSMs.getSpeedDuration());
      executor.execute();
      Assert.assertEquals("no error", 0, executor.getErrorAccount());
    }
  }

}
