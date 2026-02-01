// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.keygeneration;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_GENERATE_KEY_PAIR;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_EC_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.ckmCodeToName;

/**
 * EDDSA Keypair Generation Speed Test
 *
 * @author Lijun Liao (xipki)
 */
public class ECKeypairGenSpeedTest extends TestBase {

  private class MyExecutor extends KeypairGenExecutor {

    public MyExecutor(boolean inToken) {
      super(ckmCodeToName(mechanism) + " (NIST P-256, inToken: " +
              inToken + ") Speed", mechanism, inToken);
    }

    @Override
    protected PKCS11KeyPairSpec getMinimalKeyPairTemplate() {
      return new PKCS11KeyPairSpec().token(false)
          .keyPairType(PKCS11KeyPairType.P256);
    }

  }

  private static final long mechanism = CKM_EC_KEY_PAIR_GEN;

  @Override
  protected TestHSMs.TestHSM getHSM() {
    return TestHSMs.getHsmForSpeed();
  }

  @Test
  public void execTest() throws PKCS11Exception {
    PKCS11Token token = getToken();

    Assume.assumeTrue(ckmCodeToName(mechanism) +
            " is not supported, skip test",
        token.supportsMechanism(mechanism, CKF_GENERATE_KEY_PAIR));

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
