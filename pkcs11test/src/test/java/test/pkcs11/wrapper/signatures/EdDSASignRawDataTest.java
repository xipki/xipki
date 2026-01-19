// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.params.EDDSA_PARAMS;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_EC_EDWARDS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_EDDSA;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class EdDSASignRawDataTest {

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
    public void testEd25519() throws Exception {
      test(true);
    }

    @Test
    public void testEd448() throws Exception {
      test(false);
    }

    private void test(boolean ed25519) throws Exception {
      LOG.info("##################################################");
      LOG.info("generate signature key pair");

      final long mechCode = CKM_EDDSA;
      PKCS11Token token = getToken();
      Assume.assumeTrue(token.supportsMechanism(mechCode, CKF_SIGN));

      // be sure that your token can process the specified mechanism
      CkMechanism sigMechanism = getSupportedMechanism(mechCode, CKF_SIGN);
      if (!ed25519) {
        EDDSA_PARAMS eddsaParams = new EDDSA_PARAMS(false, new byte[0]);
        sigMechanism = new CkMechanism(mechCode, eddsaParams);
      }

      final boolean inToken = false;
      PKCS11KeyId generatedKeyPair = generateKeypair(
          ed25519 ? PKCS11KeyPairType.ED25519 : PKCS11KeyPairType.ED448,
          inToken);

      int[] dataLens = {10570, 1057, 105700};

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
        jceVerifySignature(ed25519 ? "Ed25519" : "Ed448", generatedPublicKey,
            CKK_EC_EDWARDS, dataToBeSigned, signatureValue);

        LOG.info("##################################################");
      }
    }
  }

}
