// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.crypt;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11Key;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_OAEP_PARAMS;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.security.util.KeyUtil;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_DECRYPT;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKG_MGF1_SHA1;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKG_MGF1_SHA256;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS_OAEP;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_SHA256;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_SHA_1;

/**
 * This demo shows how to use a PKCS#11 token to decrypt a session key
 * encrypted by RSA.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class RSAOaepDecryptTest {

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
    public void test() throws Exception {
      RSA_PKCS_OAEP_PARAMS params;
      String jceAlgo;
      if (getModule().getHsmVendor().getVendorEnum() == VendorEnum.SOFTHSM) {
        jceAlgo = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
        params = new RSA_PKCS_OAEP_PARAMS(CKM_SHA_1, CKG_MGF1_SHA1);
      } else {
        jceAlgo = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        params = new RSA_PKCS_OAEP_PARAMS(CKM_SHA256, CKG_MGF1_SHA256);
      }

      CkMechanism encMech = getSupportedMechanism(CKM_RSA_PKCS_OAEP, CKF_DECRYPT, params);

      final boolean inToken = false;
      PKCS11KeyId keypairId = generateKeypair(PKCS11KeyPairType.RSA2048, inToken);

      PKCS11Token token = getToken();

      byte[] data = randomBytes(16);
      PKCS11Key p11Key = token.getKey(keypairId);

      RSAPublicKey publicKey = new RSAPublicKey() {
        @Override
        public BigInteger getPublicExponent() {
          return p11Key.rsaPublicExponent();
        }

        @Override
        public String getAlgorithm() {
          return "RSA";
        }

        @Override
        public String getFormat() {
          return "";
        }

        @Override
        public byte[] getEncoded() {
          return new byte[0];
        }

        @Override
        public BigInteger getModulus() {
          return p11Key.rsaModulus();
        }
      };

      Cipher cipher = Cipher.getInstance(jceAlgo, KeyUtil.providerName(jceAlgo));
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] cipherText = cipher.doFinal(data);

      // decrypt
      byte[] decryptedData = token.decrypt(encMech, keypairId.getHandle(), cipherText);

      Assert.assertArrayEquals(data, decryptedData);
      LOG.info("finished");
    }
  }

}
