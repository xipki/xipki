// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_SIGN;

/**
 * This class demonstrates how to use the GenericSearchTemplate class.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class GenericFindTest {

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
    public void execTest() throws TokenException {
      LOG.info("##################################################");
      LOG.info("Find all signature private keys.");
      Template signatureKeyTemplate =
          Template.newPrivateKey().attr(CKA_SIGN, true);

      PKCS11Token token = getToken();
      // this find operation will find all objects that possess a CKA_SIGN
      // attribute with value true
      long[] signatureKeys = token.findObjects(signatureKeyTemplate, 99999);

      if (signatureKeys.length == 0) {
        LOG.info("There is no object with a CKA_SIGN attribute set to true.");
        return;
      }

      for (long object : signatureKeys) {
        LOG.info("handle={}, label={}", object, getLabel(object));
      }

      LOG.info("found {} objects on this token", signatureKeys.length);
    }

    private String getLabel(long hObject) throws TokenException {
      return getToken().getAttrValues(hObject,
          new AttributeTypes().label()).label();
    }
  }

}
