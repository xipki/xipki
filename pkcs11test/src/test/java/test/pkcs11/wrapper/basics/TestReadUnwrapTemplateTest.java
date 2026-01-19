// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11TemplateSpec;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

/**
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class TestReadUnwrapTemplateTest {

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
    public void execute() throws TokenException {
      PKCS11Token token = getToken();
      PKCS11SecretKeySpec template = newSecretKey(PKCS11T.CKK_AES)
          .valueLen(32)
          .unwrapTemplate(
              new PKCS11TemplateSpec()
                  .sensitive(true).wrapWithTrusted(true).sign(false))
          .wrapTemplate(
              new PKCS11TemplateSpec()
                  .keyType(PKCS11T.CKK_AES).wrapWithTrusted(true));

      System.out.println("Template before generation\n" + template);
      PKCS11KeyId keyId = token.generateKey(template);

      // test the read function
      Template attrs = token.getAttrValues(keyId.getHandle(),
          new AttributeTypes().unwrapTemplate().wrapTemplate());
      System.out.println("read unwrapTemplate: " + attrs.unwrapTemplate());
      System.out.println("read wrapTemplate: " + attrs.wrapTemplate());

      // remove object
      token.destroyKey(keyId);
    }
  }

}
