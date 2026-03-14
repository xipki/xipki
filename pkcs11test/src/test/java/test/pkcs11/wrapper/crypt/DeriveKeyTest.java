// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.crypt;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.params.ECDH1_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.pkcs11.xihsm.crypt.MontgomeryCurveEnum;
import org.xipki.security.util.WeierstraussCurveEnum;
import org.xipki.util.codec.Hex;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.math.BigInteger;
import java.util.Arrays;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_AES;

/**
 * This demo program shows how to derive a DES3 key.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class DeriveKeyTest {

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
    public void testWeierstrass() throws Exception {
      Assume.assumeTrue("Cloud HSM does not support C_DeriveKey via " +
          "CKM_ECDH1_DERIVE with kdf=CKD_NULL",
          getModule().getHsmVendor().getVendorEnum() != VendorEnum.CLOUDHSM);

      byte[] id = randomBytes(20);
      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec().token(false)
          .id(id).sensitive(true).private_(true)
          .keyPairType(PKCS11KeyPairType.P256);
      template.signVerify(true).derive(true);

      PKCS11Token token = getToken();
      PKCS11KeyId peerP11KeyId = token.generateKeyPair(template);
      LOG.info("Generated peerKeyId " + peerP11KeyId);

      WeierstraussCurveEnum curve = WeierstraussCurveEnum.P256;
      ECPoint peerPublicKey = curve.decodePoint(token.getKey(peerP11KeyId).ecPublicPoint());

      byte[][] tempKeyPair = curve.generateKeyPair(random);

      byte[] encodedECDH = peerPublicKey.multiply(
          new BigInteger(1, tempKeyPair[0])).normalize().getEncoded(false);
      byte[] agreedSk = Arrays.copyOfRange(encodedECDH, 1, 33);
      int valueLen = 24;
      if (valueLen != agreedSk.length) {
        agreedSk = Arrays.copyOfRange(agreedSk, agreedSk.length - valueLen, agreedSk.length);
      }

      LOG.info("derive key");

      PKCS11SecretKeySpec derivedKeyTemplate = newSecretKey(CKK_AES)
          .valueLen(valueLen).token(false).sensitive(false).extractable(true);

      ECDH1_DERIVE_PARAMS params = new ECDH1_DERIVE_PARAMS(PKCS11T.CKD_NULL,
          null, tempKeyPair[1]);
      CkMechanism mechanism = new CkMechanism(PKCS11T.CKM_ECDH1_DERIVE, params);

      LOG.info("Derivation Mechanism: {}", mechanism);

      long derivedKey = token.deriveKey(mechanism, peerP11KeyId.getHandle(), derivedKeyTemplate);
      byte[] agreedP11Sk = token.getAttrValues(derivedKey, new AttributeTypes().value()).value();
      Assert.assertNotNull("agreedP11Sk", agreedP11Sk);
      LOG.info("Derived key: {}", agreedP11Sk);
      Assert.assertEquals("derived key", Hex.encode(agreedSk), Hex.encode(agreedP11Sk));
    }

    // @Test
    public void testX25519() throws Exception {
      byte[] id = randomBytes(20);
      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec().token(false)
          .id(id).sensitive(true).private_(true)
          .keyPairType(PKCS11KeyPairType.X25519);
      template.signVerify(true).derive(true);

      PKCS11Token token = getToken();
      PKCS11KeyId peerP11KeyId = token.generateKeyPair(template);
      byte[] peerPublicKey = token.getKey(peerP11KeyId).ecPublicPoint();

      LOG.info("Generated peerKeyId " + peerP11KeyId);

      MontgomeryCurveEnum curve = MontgomeryCurveEnum.X25519;
      byte[][] tempKeyPair = curve.generateKeyPair(random);

      byte[] agreedSk = new byte[curve.getPublicKeySize()];
      X25519.calculateAgreement(tempKeyPair[0], 0, peerPublicKey, 0, agreedSk, 0);

      int valueLen = 16;
      if (valueLen != agreedSk.length) {
        agreedSk = Arrays.copyOfRange(agreedSk, agreedSk.length - valueLen, agreedSk.length);
      }

      LOG.info("derive key");

      PKCS11SecretKeySpec derivedKeyTemplate = newSecretKey(CKK_AES)
          .valueLen(valueLen).token(false).sensitive(false).extractable(true);

      ECDH1_DERIVE_PARAMS params = new ECDH1_DERIVE_PARAMS(PKCS11T.CKD_NULL,
          null, tempKeyPair[1]);
      CkMechanism mechanism = new CkMechanism(PKCS11T.CKM_ECDH1_DERIVE, params);

      LOG.info("Derivation Mechanism: {}", mechanism);

      long derivedKey = token.deriveKey(mechanism, peerP11KeyId.getHandle(), derivedKeyTemplate);
      byte[] agreedP11Sk = token.getAttrValues(derivedKey, new AttributeTypes().value()).value();
      Assert.assertNotNull("agreedP11Sk", agreedP11Sk);

      LOG.info("Derived key: {}", agreedP11Sk);
      Assert.assertEquals("derived key", Hex.encode(agreedSk), Hex.encode(agreedP11Sk));
    }
  }

}
