// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.crypt;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Hex;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_AES;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_SHA256;

/**
 * This demo program uses a PKCS#11 module to MAC a given file and test if the
 * MAC can be verified.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class DigestTest {

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
    public void execTest() throws TokenException {
      LOG.info("##################################################");
      LOG.info("generate secret key to hash");
      PKCS11Token token = getToken();

      byte[] prefix = randomBytes(100);
      byte[] suffix = randomBytes(120);

      PKCS11SecretKeySpec macKeyTemplate = newSecretKey(CKK_AES)
          .token(false).encrypt(true).decrypt(true);

      byte[] keyValue = randomBytes(32);
      PKCS11KeyId keyId = token.importSecretKey(keyValue, macKeyTemplate);

      LOG.info("##################################################");
      String title = "digest only the key";
      LOG.info(title);
      CkMechanism mech = new CkMechanism(CKM_SHA256);
      byte[] expHash = HashAlgo.SHA256.hash(keyValue);
      byte[] hash = token.digest(mech, keyId.getHandle());
      Assert.assertEquals(title, Hex.encode(expHash), Hex.encode(hash));

      title = "digest key with prefix and suffix";
      LOG.info(title);
      expHash = HashAlgo.SHA256.hash(prefix, keyValue, suffix);
      hash = token.digest(mech, prefix, keyId.getHandle(), suffix);
      Assert.assertEquals(title, Hex.encode(expHash), Hex.encode(hash));

      title = "digest prefix and suffix without key";
      LOG.info(title);
      expHash = HashAlgo.SHA256.hash(prefix, suffix);
      hash = token.digest(mech, prefix, 0, suffix);
      Assert.assertEquals(title, Hex.encode(expHash), Hex.encode(hash));
    }
  }

}
