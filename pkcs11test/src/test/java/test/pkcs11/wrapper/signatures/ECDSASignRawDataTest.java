// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.ExtraParams;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.util.codec.asn1.Asn1Util;
import test.pkcs11.wrapper.TestHSMs;

import java.security.MessageDigest;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_EC;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ECDSA;
import static org.xipki.pkcs11.wrapper.PKCS11T.ckmCodeToName;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class ECDSASignRawDataTest {

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

  private static abstract class Base extends SignatureTestBase {

    @Test
    public void execTest() throws Exception {
      LOG.info("##################################################");
      LOG.info("generate signature key pair");

      final long mechCode = CKM_ECDSA;
      PKCS11Token token = getToken();

      Assume.assumeTrue("Unsupported mechanism " + ckmCodeToName(mechCode),
          token.supportsMechanism(mechCode, CKF_SIGN));

      final boolean inToken = false;

      // be sure that your token can process the specified mechanism
      CkMechanism signatureMechanism = getSupportedMechanism(mechCode, CKF_SIGN);
      // Some HSM vendors return the ECDSA signature in X.962 format, we need
      // to provide the order bit to covert it to R || S.
      signatureMechanism = new CkMechanism(signatureMechanism.getMechanism(),
          signatureMechanism.getParameters());
      signatureMechanism.setExtraParams(new ExtraParams().ecOrderBitSize(256));

      PKCS11KeyId generatedKeyPair = generateKeypair(PKCS11KeyPairType.P256, inToken);
      long generatedPrivateKey = generatedKeyPair.getHandle();

      int[] dataLens = {1057, 10570, 105700};

      for (int dataLen : dataLens) {
        LOG.info("##################################################");
        LOG.info("signing data");
        byte[] dataToBeSigned = randomBytes(dataLen); // hash value
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashValue = md.digest(dataToBeSigned);

        // This signing operation is implemented in most of the drivers
        byte[] signatureValue = token.sign(signatureMechanism, generatedPrivateKey, hashValue);

        LOG.info("The signature value is: {}", Functions.toHex(signatureValue));

        long generatedPublicKey = generatedKeyPair.getPublicKeyHandle();
        // verify with JCE
        jceVerifySignature("SHA256WithECDSA", generatedPublicKey, CKK_EC,
            dataToBeSigned, Asn1Util.dsaSigPlainToX962(signatureValue));

        LOG.info("##################################################");
      }
    }
  }

}
