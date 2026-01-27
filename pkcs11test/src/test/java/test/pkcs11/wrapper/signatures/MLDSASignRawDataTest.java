// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_ML_DSA;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ML_DSA;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class MLDSASignRawDataTest {

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

  private static abstract class Base extends SignatureTestBase {

    @Test
    public void testMLDSA44() throws Exception {
      LOG.info("testMLDSA44");
      test(PKCS11KeyPairType.MLDSA44);
    }

    @Test
    public void testMLDSA65() throws Exception {
      LOG.info("testMLDSA65");
      test(PKCS11KeyPairType.MLDSA65);
    }

    @Test
    public void testMLDSA87() throws Exception {
      LOG.info("testMLDSA87");
      test(PKCS11KeyPairType.MLDSA87);
    }

    private void test(PKCS11KeyPairType.MLDSA keyPairType) throws Exception {
      LOG.info("##################################################");
      LOG.info("generate signature key pair");

      PKCS11Token token = getToken();
      CkMechanism sigMechanism = getSupportedMechanism(CKM_ML_DSA, CKF_SIGN);

      final boolean inToken = false;

      byte[] id = new byte[20];
      new Random().nextBytes(id);

      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec()
          .token(inToken).id(id)
          .signVerify(true).sensitive(true).private_(true)
          .keyPairType(keyPairType);

      PKCS11KeyId generatedKeyPair =
          token.generateKeyPair(template);

      int[] dataLens = {1057, 10570, 105700};

      for (int dataLen : dataLens) {
        LOG.info("##################################################");
        LOG.info("signing data");
        byte[] dataToBeSigned = randomBytes(dataLen); // hash value

        // This signing operation is implemented in most of the drivers
        long generatedPrivateKey = generatedKeyPair.getHandle();
        byte[] signatureValue = token.sign(sigMechanism,
            generatedPrivateKey, dataToBeSigned);
        LOG.info("The signature value is: {}", Functions.toHex(signatureValue));

        // verify signature
        long generatedPublicKey = generatedKeyPair.getPublicKeyHandle();

        // verify with JCE
        String stdMldsaName = PKCS11T.getStdMldsaName(
            keyPairType.getVariant());
        jceVerifySignature(stdMldsaName, generatedPublicKey, CKK_ML_DSA,
            dataToBeSigned, signatureValue);

        LOG.info("##################################################");
      }
    }
  }

}
