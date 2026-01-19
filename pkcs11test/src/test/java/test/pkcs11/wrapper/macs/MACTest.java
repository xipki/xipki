// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.macs;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_GENERATE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_GENERIC_SECRET;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_SHA256_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_GENERIC_SECRET_KEY_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_SHA256_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_SHA256_KEY_GEN;

/**
 * This demo program uses a PKCS#11 module to MAC a given file and test if the
 * MAC can be verified.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class MACTest {

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
    public void main() throws TokenException {
      CkMechanism signatureMechanism =
          getSupportedMechanism(CKM_SHA256_HMAC, CKF_SIGN);

      LOG.info("##################################################");
      LOG.info("generate secret MAC key");

      PKCS11Token token = getToken();

      PKCS11KeyId secretMACKey;
      int keyBytesLen = 32;

      long[] ckks = {CKK_GENERIC_SECRET, CKK_SHA256_HMAC};
      long[] ckms = {CKM_GENERIC_SECRET_KEY_GEN, CKM_SHA256_KEY_GEN};

      Long ckm = null;
      long ckk = CKK_GENERIC_SECRET;
      for (int i = 0; i < ckms.length; i++) {
        if (token.supportsMechanism(ckms[i], CKF_GENERATE)) {
          ckm = ckms[i];
          ckk = ckks[i];
        }
      }

      PKCS11SecretKeySpec macKeyTemplate = newSecretKey(ckk)
          .token(false).sign(true).verify(true);

      if (ckm == null) {
        LOG.info("import secret MAC key (generation not supported)");
        byte[] keyValue = new byte[keyBytesLen];
        new SecureRandom().nextBytes(keyValue);
        secretMACKey = token.importSecretKey(keyValue, macKeyTemplate);
      } else {
        LOG.info("generate secret MAC key");
        macKeyTemplate.valueLen(keyBytesLen);
        secretMACKey = token.generateKey(macKeyTemplate);
      }

      LOG.info("##################################################");
      byte[] rawData = randomBytes(10570);

      byte[] macValue = token.sign(signatureMechanism,
          secretMACKey.getHandle(), rawData);
      LOG.info("The MAC value is: {}",
          new BigInteger(1, macValue).toString(16));

      LOG.info("##################################################");
      LOG.info("verification of the MAC... ");

      // TODO
      LOG.info("##################################################");
    }
  }

}
