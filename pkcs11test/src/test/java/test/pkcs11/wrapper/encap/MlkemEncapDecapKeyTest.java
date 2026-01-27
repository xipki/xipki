// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encap;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_ENCAPSULATE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_AES;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ML_KEM;

/**
 * This demo program uses a PKCS#11 module to encapsulate and decapsulate a
 * secret key.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class MlkemEncapDecapKeyTest {

  public static class Cloudhsm extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.cloudhsm();
    }

  }

  public static class CloudhsmVendorGcm extends Base {

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
    public void mlkem512() throws TokenException {
      testMlkem(PKCS11KeyPairType.MLKEM512);
    }

    @Test
    public void mlkem768() throws TokenException {
      testMlkem(PKCS11KeyPairType.MLKEM768);
    }

    @Test
    public void mlkem1024() throws TokenException {
      testMlkem(PKCS11KeyPairType.MLKEM1024);
    }

    private void testMlkem(PKCS11KeyPairType keyPairType)
        throws TokenException {
      Assume.assumeTrue("ML-KEM unsupported",
          getToken().supportsMechanism(CKM_ML_KEM, CKF_ENCAPSULATE));

      LOG.info("##################################################");
      LOG.info("generate ML-LEM key pair {}", keyPairType);

      PKCS11KeyPairSpec spec = new PKCS11KeyPairSpec()
          .keyPairType(keyPairType).token(false)
          .encapsulate(true).decapsulate(true);

      PKCS11Token token = getToken();
      PKCS11KeyId keypairId = token.generateKeyPair(spec);

      // be sure that your token can process the specified mechanism
      CkMechanism mech = getSupportedMechanism(
          CKM_ML_KEM, CKF_ENCAPSULATE, null);

      Template template = token.getAttrValues(keypairId.getPublicKeyHandle(),
          new AttributeTypes().parameterSet().value());
      MLKEMParameters mlkemParams;
      long variant = template.parameterSet();
      if (variant == PKCS11T.CKP_ML_KEM_512) {
        mlkemParams = MLKEMParameters.ml_kem_512;
      } else if (variant == PKCS11T.CKP_ML_KEM_768) {
        mlkemParams = MLKEMParameters.ml_kem_768;
      } else if (variant == PKCS11T.CKP_ML_KEM_1024) {
        mlkemParams = MLKEMParameters.ml_kem_1024;
      } else {
        throw new TokenException(
          "invalid variant 0x" + Functions.toFullHex(variant));
      }

      byte[] value = template.value();
      MLKEMPublicKeyParameters pk = new MLKEMPublicKeyParameters(
          mlkemParams, value);
      MLKEMGenerator gen = new MLKEMGenerator(random);
      SecretWithEncapsulation encapKey = gen.generateEncapsulated(pk);

      PKCS11SecretKeySpec aesKeySpec = new PKCS11SecretKeySpec()
          .keyType(CKK_AES).encrypt(true).decrypt(true).token(false);

      long hKey2 = token.decapsulateKey(
          mech, keypairId.getHandle(), encapKey.getEncapsulation(), aesKeySpec);

      LOG.info("##################################################");
    }
  }

}
