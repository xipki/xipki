// Copyright (c) 2013-2026 xipki. All rights reserved.
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

  /**
   * Nested class Cloudhsm.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Cloudhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.cloudhsm();
    }
  }

  /**
   * Nested class Luna.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Luna extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.luna();
    }
  }

  /**
   * Nested class Ncipher.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Ncipher extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.ncipher();
    }
  }

  /**
   * Nested class Sansec.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Sansec extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.sansec();
    }
  }

  /**
   * Nested class Tass.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Tass extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.tass();
    }
  }

  /**
   * Nested class Softhsm.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Softhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.softhsm();
    }
  }

  /**
   * Nested class Utimaco.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Utimaco extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.utimaco();
    }
  }

  /**
   * Nested class Xihsm.
   *
   * @author Lijun Liao (xipki)
   */
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
