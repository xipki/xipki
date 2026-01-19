// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Assume;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.util.codec.Hex;
import test.pkcs11.wrapper.util.KeyUtil;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 *
 * @author Lijun Liao (xipki)
 */
public abstract class TestBase {

  // plen: 2048, qlen: 256
  public static final BigInteger DSA_P = new BigInteger(
      "E13AC60336C29FAF1B48393D80C74B781E15E23E3F59F0827190FF016720A8E0"
      + "DAC2D4FF699EBA2196E1B9815ECAE0506441A4BC4DA97E97F2723A808EF6B634"
      + "3968906137B04B23F6540FC4B9D7C0A46635B6D52AEDD08347370B9BE43A7222"
      + "807655CB5ED480F4C66128357D0E0A2C62785DC38160645661FA569ADCE46D3B"
      + "3BFAB114613436242855F5717143D51FB365972F6B8695C2186CBAD1E8C5B4D3"
      + "1AD70876EBDD1C2191C5FB6C4804E0D38CBAA054FC7AFD25E0F2735F726D8A31"
      + "DE97431BFB6CF1AD563811830131E7D5E5117D92389406EF436A8077E69B8795"
      + "18436E33A9F221AB3A331680D0345B316F5BEBDA8FBF70612BEC734272E760BF", 16);

  public static final BigInteger DSA_Q = new BigInteger(
      "9CF2A23A8F95FEFB0CA67212991AC172FDD3F4D70401B684C3E4223D46D090E5", 16);

  public static final BigInteger DSA_G = new BigInteger(
      "1CBEF6EEB9E73C5997BF64CA8BCC33CDC6AFC5601B86FDE1B0AC4C34066DFBF9"
      + "9B80CCE264C909B32CF88CE09CB73476C0A6E701092E09C93507FE3EBD425B75"
      + "8AE3C5E3FDC1076AF237C5EF40A790CF6555EB3408BCEF212AC5A1C125A7183D"
      + "24935554C0D258BF1F6A5A6D05C0879DB92D32A0BCA3A85D42F9B436AE97E62E"
      + "0E30E53B8690D8585493D291969791EA0F3B062645440587C031CD2880481E0B"
      + "E3253A28EFFF3ACEB338A2FE4DB8F652E0FDA277268B73D5E532CF9E4E2A1CAB"
      + "738920F760012DD9389F35E0AA7C8528CE173934529397DABDFAA1E77AF83FAD"
      + "629AC102596885A06B5C670FFA838D37EB55FE7179A88F6FF927B37E0F827726", 16);

  protected static final SecureRandom random = new SecureRandom();

  protected final Logger LOG = LoggerFactory.getLogger(getClass());

  protected InputStream getResourceAsStream(String path) {
    return getClass().getResourceAsStream(path);
  }

  public static byte[] randomBytes(int len) {
    byte[] ret = new byte[len];
    random.nextBytes(ret);
    return ret;
  }

  protected abstract TestHSMs.TestHSM getHSM();

  protected PKCS11Token getToken() {
    return getHSM().getToken();
  }

  protected PKCS11Module getModule() {
    return getHSM().getModule();
  }

  protected void assertSupport(long mechCode, long flagBit) {
    Assume.assumeTrue("Mechanism " + ckmCodeToName(mechCode) + " for " +
        codeToName(Category.CKF_MECHANISM, flagBit) + " is not supported",
        getToken().supportsMechanism(mechCode, flagBit));
  }

  protected void assertCanGenerate(PKCS11KeyPairSpec keyPairSpec) {
    Assume.assumeTrue("Can not generate Keypair " +
            ckkCodeToName(keyPairSpec.keyPairType().getKeyType()),
        keyPairSpec.canGenerate(getToken()));
  }

  protected void assertCanGenerate(PKCS11SecretKeySpec keySpec) {
    Assume.assumeTrue("Can not generate secret key " +
            ckkCodeToName(keySpec.keyType()),
    keySpec.canGenerate(getToken()));
  }

  protected CkMechanism getSupportedMechanism(long mechCode, long flagBit)
      throws PKCS11Exception {
    return getSupportedMechanism(mechCode, flagBit, null);
  }

  protected CkMechanism getSupportedMechanism(
      long mechCode, long flagBit, CkParams parameters)
      throws PKCS11Exception {
    assertSupport(mechCode, flagBit);
    return new CkMechanism(mechCode, parameters);
  }

  protected PKCS11KeyId generateKeypair(
      PKCS11KeyPairType keyPairType, boolean inToken)
      throws TokenException {
    byte[] id = new byte[20];
    new Random().nextBytes(id);

    PKCS11KeyPairSpec template = new PKCS11KeyPairSpec()
        .token(inToken).id(id)
        .sensitive(true).private_(true)
        .keyPairType(keyPairType);

    long keyType = keyPairType.getKeyType();
    if (keyType == CKK_RSA || keyType == CKK_VENDOR_SM2 || keyType == CKK_EC) {
      template.signVerify(true).decryptEncrypt(true);
    } else if (keyType == CKK_DSA || keyType == CKK_ML_DSA
        || keyType == CKK_EC_EDWARDS) {
      template.signVerify(true);
    } else if (keyType == CKK_ML_KEM ||keyType == CKK_EC_MONTGOMERY) {
      template.decryptEncrypt(true);
    } else {
      throw new TokenException("unknown key type " + ckkCodeToName(keyType));
    }

    assertCanGenerate(template);

    return getToken().generateKeyPair(template);
  }

  protected PKCS11SecretKeySpec newSecretKey(long keyType) {
    return new PKCS11SecretKeySpec().keyType(keyType);
  }

  protected Template newPublicKey(long keyTye) {
    return Template.newPublicKey(keyTye);
  }

  protected Template newPrivateKey(long keyType) {
    return Template.newPrivateKey(keyType);
  }

  protected PublicKey generateJCEPublicKey(long p11Key, Long keyType)
      throws InvalidKeySpecException, TokenException {
    PKCS11Token token = getToken();
    if (keyType == null) {
      keyType = token.getAttrValues(p11Key,
          new AttributeTypes().keyType()).keyType();
    }

    if (keyType == CKK_RSA) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().modulus().publicExponent());
      return KeyUtil.generateRSAPublicKey(
          new RSAPublicKeySpec(attrValues.modulus(),
          attrValues.publicExponent()));
    } else if (keyType == CKK_DSA) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().value().prime().subprime().base()); // y, p, q, g

      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(
          new BigInteger(1, attrValues.value()),
          attrValues.prime(), attrValues.subprime(), attrValues.base());
      return KeyUtil.generateDSAPublicKey(keySpec);
    } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS
        || keyType == CKK_EC_MONTGOMERY || keyType == CKK_VENDOR_SM2) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().ecPoint().ecParams());
      byte[] encodedPoint = attrValues.ecPoint();
      byte[] ecParams = attrValues.ecParams();
      if (ecParams == null && keyType == CKK_VENDOR_SM2) {
        // GMObjectIdentifiers.sm2p256v1.getEncoded();
        ecParams = Hex.decode("06082a811ccf5501822d");
      }

      if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        assert ecParams != null;

        String oidStr = Functions.getCurveOID(ecParams);
        if (oidStr == null) {
          throw new TokenException(
              "unsupported ecParams " + Hex.encode(ecParams));
        }

        ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier(oidStr);

        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(algOid), encodedPoint);

        return KeyUtil.generatePublicKey(pkInfo);
      } else {
        return KeyUtil.createECPublicKey(ecParams, encodedPoint);
      }
    } else if (keyType == CKK_ML_DSA) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().parameterSet().value());

      byte[] value = attrValues.value();
      long variant = attrValues.parameterSet();

      ASN1ObjectIdentifier oid =
          (variant == CKP_ML_DSA_44) ? NISTObjectIdentifiers.id_ml_dsa_44
              : (variant == CKP_ML_DSA_65)
                ? NISTObjectIdentifiers.id_ml_dsa_65
              : NISTObjectIdentifiers.id_ml_dsa_87;

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
          new AlgorithmIdentifier(oid), value);
      return KeyUtil.generatePublicKey(pkInfo);
    } else if (keyType == CKK_ML_KEM) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().value().parameterSet());
      byte[] value = attrValues.value();
      long variant = attrValues.parameterSet();

      ASN1ObjectIdentifier oid =
          (variant == CKP_ML_KEM_512)
              ? NISTObjectIdentifiers.id_alg_ml_kem_512
              : (variant == CKP_ML_KEM_768)
                  ? NISTObjectIdentifiers.id_alg_ml_kem_768
                  : NISTObjectIdentifiers.id_alg_ml_kem_1024;

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
          new AlgorithmIdentifier(oid), value);
      return KeyUtil.generatePublicKey(pkInfo);
    } else {
      throw new InvalidKeySpecException("unknown publicKey type " +
          ckkCodeToName(keyType));
    }
  } // method generatePublicKey

  protected static List<Long> getMechanismList(Token token) {
    long[] supportedMechanisms = token.getMechanismList();
    List<Long> list = new ArrayList<>(supportedMechanisms.length);
    for (long mech : supportedMechanisms) {
      list.add(mech);
    }
    return list;
  }

}
