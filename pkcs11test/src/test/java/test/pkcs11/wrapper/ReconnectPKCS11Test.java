// Copyright (c) 2025 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.LogPKCS11;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.type.CkInfo;

/**
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public abstract class ReconnectPKCS11Test {

  public static class Cloudhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.cloudhsm();
    }
  }

  public static class Luna extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.luna();
    }
  }

  public static class Ncipher extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.ncipher();
    }
  }

  public static class Sansec extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.sansec();
    }
  }

  public static class Tass extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.tass();
    }
  }

  public static class Softhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.softhsm();
    }
  }

  public static class Utimaco extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.utimaco();
    }
  }

  public static class Xihsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.xihsm();
    }
  }

  private static abstract class Base extends TestBase {

    @Test
    public void test() throws PKCS11Exception {
      LogPKCS11 pkcs11 = getModule().getPKCS11();
      CkInfo mi1 = pkcs11.C_GetInfo();
      Assert.assertNotNull("mi1", mi1);
      pkcs11.reconnect();

      CkInfo mi2 = pkcs11.C_GetInfo();
      Assert.assertNotNull("mi2", mi2);
      Assert.assertEquals(mi1, mi2);
    }

  }

}
