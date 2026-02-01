// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_RSA;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_9796;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS_OAEP;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_PKCS_PSS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_RSA_X_509;

/**
 * This demo program generates a 2048-bit RSA key-pair on the token.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class RSAGenerateKeyPairTest {

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
    public void execTest() throws Exception {
      LOG.info("##################################################");
      LOG.info("Generating new 2048 bit RSA key-pair... ");

      PKCS11Token token = getToken();

      // first check out what attributes of the keys we may set
      CkMechanismInfo mechanismInfo =
          token.supportsMechanism(CKM_RSA_PKCS, CKF_SIGN)
              ? token.getMechanismInfo(CKM_RSA_PKCS)
              : token.supportsMechanism(CKM_RSA_X_509, CKF_SIGN)
              ? token.getMechanismInfo(CKM_RSA_X_509)
              : token.supportsMechanism(CKM_RSA_9796, CKF_SIGN)
              ? token.getMechanismInfo(CKM_RSA_9796)
              : token.supportsMechanism(CKM_RSA_PKCS_PSS, CKF_SIGN)
              ? token.getMechanismInfo(CKM_RSA_PKCS_OAEP)
              : null;

      byte[] id = new byte[20];
      new Random().nextBytes(id);

      // set the general attributes for the public key
      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec()
          .token(true).id(id).sensitive(true).private_(true)
          .keyPairType(PKCS11KeyPairType.RSA2048);
      assertCanGenerate(template);

      // set the attributes in a way netscape does, this should work with most
      // tokens
      if (mechanismInfo != null) {
        ECGenerateKeyPairTest.fillTemplate(template, mechanismInfo);
      } else {
        // if we have no information we assume these attributes
        template.signVerify(true).decryptEncrypt(true);
      }

      PKCS11KeyId generatedKeyPair = token.generateKeyPair(template);
      long generatedPublicKey = generatedKeyPair.getPublicKeyHandle();
      long generatedPrivateKey = generatedKeyPair.getHandle();
      // now we may work with the keys...

      try {
        LOG.info("Success");
        LOG.info("The public key is {}", generatedPublicKey);
        LOG.info("The private key is {}", generatedPrivateKey);
        LOG.info("__________________________________________________");

        LOG.info("##################################################");
        Template attrValues = token.getAttrValues(generatedPublicKey,
            new AttributeTypes().modulus().publicExponent());

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(
            attrValues.modulus(), attrValues.publicExponent());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey javaRsaPublicKey = (RSAPublicKey)
            keyFactory.generatePublic(rsaPublicKeySpec);
        X509EncodedKeySpec x509EncodedPublicKey =
            keyFactory.getKeySpec(javaRsaPublicKey, X509EncodedKeySpec.class);

        x509EncodedPublicKey.getEncoded();

        // now we try to search for the generated keys
        LOG.info("##################################################");
        LOG.info("Trying to search for the public key of the generated " +
            "key-pair by ID: {}", Functions.toHex(id));
        // set the search template for the public key
        Template exportRsaPublicKeyTemplate =
            newPublicKey(CKK_RSA).id(id);

        long[] foundPublicKeys =
            token.findObjects(exportRsaPublicKeyTemplate, 1);
        if (foundPublicKeys.length != 1) {
          LOG.error("Error: Cannot find the public key under the given ID!");
        } else {
          LOG.info("Found public key: {}", foundPublicKeys[0]);
        }

        LOG.info("##################################################");
      } finally {
        token.destroyObject(generatedPrivateKey);
        token.destroyObject(generatedPublicKey);
      }

    }
  }

}
