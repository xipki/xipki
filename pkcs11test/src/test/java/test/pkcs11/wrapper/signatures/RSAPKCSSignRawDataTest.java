// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestHSMs;

import java.math.BigInteger;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_RSA;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_SHA256_RSA_PKCS;
import static org.xipki.pkcs11.wrapper.PKCS11T.ckmCodeToName;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class RSAPKCSSignRawDataTest {

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
    public void main() throws Exception {
      LOG.info("##################################################");
      LOG.info("generate signature key pair");
      final long mechCode = CKM_SHA256_RSA_PKCS;

      PKCS11Token token = getToken();

      Assume.assumeTrue("Unsupported mechanism " + ckmCodeToName(mechCode),
          token.supportsMechanism(mechCode, CKF_SIGN));

      // be sure that your token can process the specified mechanism
      CkMechanism signatureMechanism =
          getSupportedMechanism(mechCode, CKF_SIGN);

      final boolean inToken = false;
      PKCS11KeyId generatedKeyPair =
          generateKeypair(PKCS11KeyPairType.RSA_2048, inToken);
      long generatedPrivateKey = generatedKeyPair.getHandle();

      int[] dataLens = {1057, 10570, 105700};
      for (int dataLen : dataLens) {
        LOG.info("##################################################");
        LOG.info("signing data");
        byte[] dataToBeSigned = randomBytes(dataLen); // hash value

        // This signing operation is implemented in most of the drivers
        byte[] signatureValue = token.sign(signatureMechanism,
            generatedPrivateKey, dataToBeSigned);

        LOG.info("The signature value is: {}",
            new BigInteger(1, signatureValue).toString(16));

        // verify
        long generatedPublicKey = generatedKeyPair.getPublicKeyHandle();

        // verify with JCE
        jceVerifySignature("SHA256withRSA", generatedPublicKey, CKK_RSA,
            dataToBeSigned, signatureValue);

        LOG.info("##################################################");
      }
    }
  }

}
