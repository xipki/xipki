// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package test.pkcs11.wrapper.visibility;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.vendor.HsmVendor;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

/**
 * Visibility test
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class SecretKeyVisibilityTest {

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
      return TestHSMs.luna();
    }
  }

  public static class Sansec extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.sansec();
    }
  }

  public static class Softhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.softhsm();
    }
  }

  public static class Tass extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.tass();
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
    public void testTF() throws Exception {
      testVisibility(true, false);
    }

    @Test
    public void testTT() throws Exception {
      testVisibility(true, true);
    }

    @Test
    public void testFF() throws Exception {
      testVisibility(false, false);
    }

    @Test
    public void testFT() throws Exception {
      testVisibility(false, true);
    }

    private void testVisibility(boolean inToken, boolean privateObj)
        throws Exception {
      TestHSMs.TestHSM hsm = getHSM();
      byte[] soPin = hsm.getSoPin();
      Assume.assumeNotNull((Object) soPin);

      PKCS11SecretKeySpec spec = new PKCS11SecretKeySpec()
          .keyType(PKCS11T.CKK_AES).valueLen(32)
          .label("aes-visibility-test-" + System.currentTimeMillis())
          .encrypt(true).decrypt(true).sensitive(true).extractable(false)
          .token(inToken).private_(privateObj);

      PKCS11Token token = hsm.getToken();
      PKCS11KeyId keyId = token.generateKey(spec);

      try {
        token.logout();
        token.loginSo(soPin);
        PKCS11KeyId newKeyId = null;
        try {
          newKeyId = token.getKeyId(keyId.getId(), keyId.getLabel());
        } catch (TokenException e) {
        }

        HsmVendor vendor = getHSM().getModule().getHsmVendor();

        VendorEnum vendorEnum = vendor.getVendorEnum();
        boolean expectedFound = !privateObj
            || (vendorEnum == VendorEnum.CLOUDHSM
                || vendorEnum == VendorEnum.TASS);

        if (expectedFound) {
          Assert.assertNotNull("SecretKey shall be visible for SO user",
              newKeyId);
        } else {
          Assert.assertNull("SecretKey shall not be visible for SO user",
              newKeyId);
        }
      } finally {
        token.logoutSo();
        token.loginUser();
        token.destroyObjectsByIdLabel(keyId.getId(), keyId.getLabel());
      }
    }
  }

}
