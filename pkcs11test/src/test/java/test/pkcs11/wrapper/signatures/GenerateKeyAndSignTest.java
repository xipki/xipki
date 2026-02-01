// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.signatures;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS;

/**
 * This demo program generates a 1024-bit RSA key-pair on the token and signs
 * some data with it.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class GenerateKeyAndSignTest {

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
    public void execTest() throws TokenException {
      LOG.info("##################################################");
      LOG.info("Generating new {} bit RSA key-pair...", 1024);

      final boolean inToken = false;
      PKCS11KeyId generatedKeyPair = generateKeypair(
          PKCS11KeyPairType.RSA1024, inToken);
      long generatedRSAPublicKey = generatedKeyPair.getPublicKeyHandle();
      long generatedRSAPrivateKey = generatedKeyPair.getHandle();
      // no we may work with the keys...

      LOG.info("Success");
      LOG.info("The  public key is {}", generatedRSAPublicKey);
      LOG.info("The private key is {}", generatedRSAPrivateKey);

      LOG.info("##################################################");
      LOG.info("Signing Data... ");

      CkMechanism signatureMechanism = new CkMechanism(CKM_RSA_PKCS);
      byte[] dataToBeSigned = "12345678901234567890123456789012345".getBytes();
      byte[] signatureValue = getToken().sign(signatureMechanism,
          generatedRSAPrivateKey, dataToBeSigned);
      LOG.info("Finished");
      LOG.info("Signature Value: {}", Functions.toHex(signatureValue));
      LOG.info("##################################################");
    }
  }

}
