// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

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
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

/**
 * This demo program generates an MLDSA key-pair on the token.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class MLDSAGenerateKeyPairTest {

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
    public void generateMldsa44() throws Exception {
      LOG.info("##################################################");
      LOG.info("Generating new MLDSA44 key-pair... ");
      generateMldsaKeypair(PKCS11KeyPairType.MLDSA44);
    }

    @Test
    public void generateMldsa65() throws Exception {
      LOG.info("##################################################");
      LOG.info("Generating new MLDSA65 key-pair... ");
      generateMldsaKeypair(PKCS11KeyPairType.MLDSA65);
    }

    @Test
    public void generateMldsa87() throws Exception {
      LOG.info("##################################################");
      LOG.info("Generating new MLDSA87 key-pair... ");
      generateMldsaKeypair(PKCS11KeyPairType.MLDSA87);
    }

    private void generateMldsaKeypair(PKCS11KeyPairType keyPairType)
        throws TokenException {
      PKCS11Token token = getToken();

      byte[] id = new byte[20];
      new Random().nextBytes(id);

      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec()
          .token(true).id(id).sensitive(true).private_(true).signVerify(true)
          .keyPairType(keyPairType);
      assertCanGenerate(template);

      PKCS11KeyId generatedKeyPair = token.generateKeyPair(template);
      long generatedPublicKey = generatedKeyPair.getPublicKeyHandle();
      long generatedPrivateKey = generatedKeyPair.getHandle();
      // no we may work with the keys...

      try {
        LOG.info("Success");
        LOG.info("The public key is {}", generatedPublicKey);
        LOG.info("The private key is {}", generatedPrivateKey);

        LOG.info("##################################################");
        Template attrs = token.getAttrValues(generatedPublicKey,
            new AttributeTypes().parameterSet().value());
        byte[] pkValue = attrs.value();
        Long mldsaVariant = attrs.parameterSet();

        LOG.info("Public Key: {}", Functions.toHex(pkValue));
        LOG.info("Public Key (ML-DSA Variant): {}",
            PKCS11T.getStdMldsaName(mldsaVariant));

        // now we try to search for the generated keys
        LOG.info("##################################################");
        LOG.info("Trying to search for the public key of the generated " +
            "key-pair by ID: {}", Functions.toHex(id));
        // set the search template for the public key
        Template exportPublicKeyTemplate =
            newPublicKey(PKCS11T.CKK_ML_DSA).attr(PKCS11T.CKA_ID, id);

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
