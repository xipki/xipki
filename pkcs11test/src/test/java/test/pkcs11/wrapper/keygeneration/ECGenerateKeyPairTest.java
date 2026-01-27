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
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * This demo program generates an EC key-pair on the token.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class ECGenerateKeyPairTest {

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
      LOG.info("Generating new EC (curve secp256r1) key-pair... ");

      PKCS11Token token = getToken();
      // first check out what attributes of the keys we may set
      CkMechanismInfo mechanismInfo = null;
      if (token.supportsMechanism(CKM_ECDSA, CKF_SIGN)) {
        mechanismInfo = token.getMechanismInfo(CKM_ECDSA);
      }

      final long mechCode = CKM_EC_KEY_PAIR_GEN;
      if (!token.supportsMechanism(mechCode, CKF_GENERATE_KEY_PAIR)) {
        System.out.println("Unsupported mechanism " + ckmCodeToName(mechCode));
        return;
      }

      byte[] id = new byte[20];
      new Random().nextBytes(id);

      // set the general attributes for the public key
      // OID: 1.2.840.10045.3.1.7 (secp256r1, alias NIST P-256)
      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec()
          .id(id).token(true).sensitive(true).private_(true)
          .keyPairType(PKCS11KeyPairType.EC_P256);

      // set the attributes in a way netscape does, this should work with most
      // tokens
      if (mechanismInfo != null) {
        fillTemplate(template, mechanismInfo);
      } else {
        // if we have no information we assume these attributes
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
            new AttributeTypes().ecPoint().ecParams());
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
            newPublicKey(CKK_EC).attr(CKA_ID, id);

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

  static void fillTemplate(PKCS11KeyPairSpec template,
                           CkMechanismInfo signatureMechanismInfo) {
    template
        .signVerify(
            signatureMechanismInfo.hasFlagBit(CKF_SIGN),
            signatureMechanismInfo.hasFlagBit(CKF_VERIFY))
        .signVerifyRecover(
            signatureMechanismInfo.hasFlagBit(CKF_SIGN_RECOVER),
            signatureMechanismInfo.hasFlagBit(CKF_VERIFY_RECOVER))
        .decryptEncrypt(
            signatureMechanismInfo.hasFlagBit(CKF_DECRYPT),
            signatureMechanismInfo.hasFlagBit(CKF_ENCRYPT))
        .unwrapWrap(
            signatureMechanismInfo.hasFlagBit(CKF_UNWRAP),
            signatureMechanismInfo.hasFlagBit(CKF_WRAP))
        .derive(signatureMechanismInfo.hasFlagBit(CKF_DERIVE));
  }

}
