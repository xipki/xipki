// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_ID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_VENDOR_SM2;

/**
 * This demo program generates an EC key-pair on the token.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class Sm2GenerateKeyPairTest {

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
      LOG.info("##################################################");
      LOG.info("Generating new EC (curve sm2p256v1) key-pair... ");

      PKCS11Token token = getToken();

      byte[] id = new byte[20];
      new Random().nextBytes(id);

      PKCS11KeyPairSpec template =
          new PKCS11KeyPairSpec().id(id).token(true)
              .sensitive(true).private_(true)
              .signVerify(true).decryptEncrypt(true)
              .keyPairType(PKCS11KeyPairType.SM2);
      assertCanGenerate(template);

      PKCS11KeyId generatedKeyPair = token.generateKeyPair(template);
      long generatedPublicKey = generatedKeyPair.getPublicKeyHandle();
      long generatedPrivateKey = generatedKeyPair.getHandle();
      // now we may work with the keys...

      try {
        LOG.info("Success");
        LOG.info("The public key is {}", generatedPublicKey);
        LOG.info("The private key is {}", generatedPrivateKey);

        LOG.info("##################################################");
        Template attrs = token.getAttrValues(generatedPublicKey,
            new AttributeTypes().ecPoint().ecParams());
        byte[] encodedPoint = attrs.ecPoint();
        byte[] curveOid = attrs.ecParams();

        LOG.info("Public Key (Point): {}", Functions.toHex(encodedPoint));
        LOG.info("Public Key (Curve OID): {}", Functions.toHex(curveOid));

        // now we try to search for the generated keys
        LOG.info("##################################################");
        LOG.info("Trying to search for the public key of the generated " +
            "key-pair by ID: {}", Functions.toHex(id));
        // set the search template for the public key
        Template exportPublicKeyTemplate =
            newPublicKey(CKK_VENDOR_SM2).attr(CKA_ID, id);

        long[] foundPublicKeys = token.findObjects(exportPublicKeyTemplate, 1);
        if (foundPublicKeys.length != 1) {
          LOG.error("Error: Cannot find the public key under the given ID!");
        } else {
          LOG.info("Found public key {}", foundPublicKeys[0]);
        }

        LOG.info("##################################################");
      } finally {
        token.destroyObject(generatedPrivateKey);
        token.destroyObject(generatedPublicKey);
      }

    }
  }

}
