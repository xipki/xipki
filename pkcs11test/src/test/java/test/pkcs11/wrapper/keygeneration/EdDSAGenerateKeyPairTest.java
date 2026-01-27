// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Assume;
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
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_ID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_GENERATE_KEY_PAIR;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_EC_EDWARDS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_EC_EDWARDS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_EDDSA;

/**
 * This demo program generates an Ed25519 key-pair on the token.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class EdDSAGenerateKeyPairTest {

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
    public void generateEd25519() throws Exception {
      LOG.info("##################################################");
      LOG.info("Generating new Ed25519 key-pair by OID... ");
      // OID: 1.3.101.112 (Ed25519)
      generateEdwardsKeypair(PKCS11KeyPairType.ED25519);
    }

    @Test
    public void generateEd448() throws Exception {
      LOG.info("##################################################");
      LOG.info("Generating new Ed448 key-pair by OID... ");
      // OID: 1.3.101.113 (Ed448)
      generateEdwardsKeypair(PKCS11KeyPairType.ED448);
    }

    private void generateEdwardsKeypair(PKCS11KeyPairType keyPairType)
        throws TokenException {
      PKCS11Token token = getToken();
      final long mechCode = CKM_EC_EDWARDS_KEY_PAIR_GEN;
      Assume.assumeTrue(token.supportsMechanism(mechCode,
          CKF_GENERATE_KEY_PAIR));

      // first check out what attributes of the keys we may set
      CkMechanismInfo mechanismInfo = null;
      if (token.supportsMechanism(CKM_EDDSA, CKF_SIGN)) {
        mechanismInfo = token.getMechanismInfo(CKM_EDDSA);
      }

      byte[] id = new byte[20];
      new Random().nextBytes(id);

      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec()
          .token(true).id(id).sensitive(true).private_(true)
          .keyPairType(keyPairType);

      // set the attributes in the way netscape does, this should work with most
      // tokens
      if (mechanismInfo != null) {
        ECGenerateKeyPairTest.fillTemplate(template, mechanismInfo);
      } else {
        // if we have no information, we assume these attributes
        template.signVerify(true).decryptEncrypt(true);
      }

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
            new AttributeTypes().ecParams().ecPoint());
        byte[] encodedPoint = attrs.ecPoint();
        byte[] ecParams = attrs.ecParams();

        LOG.info("Public Key (Point): {}", Functions.toHex(encodedPoint));
        LOG.info("Public Key (EC Params): {}", Functions.toHex(ecParams));

        // now we try to search for the generated keys
        LOG.info("##################################################");
        LOG.info("Trying to search for the public key of the generated " +
            "key-pair by ID: {}", Functions.toHex(id));
        // set the search template for the public key
        Template exportPublicKeyTemplate =
            newPublicKey(CKK_EC_EDWARDS).attr(CKA_ID, id);

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
