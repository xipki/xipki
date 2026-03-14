// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.Assume;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.Functions;
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
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.logging.LogManager;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 *
 * @author Lijun Liao (xipki)
 */
public abstract class TestBase {

  protected static final SecureRandom random = new SecureRandom();

  protected final Logger LOG = LoggerFactory.getLogger(getClass());

  static {
    // No system property set, try to load from classpath
    try (InputStream is = TestBase.class.getClassLoader()
        .getResourceAsStream("logging.properties")) {
      if (is != null) {
        LogManager.getLogManager().readConfiguration(is);
        System.out.println("JUL: Loaded configuration from classpath.");
      }
    } catch (IOException e) {
        System.err.println("JUL: Could not load default logging.properties: " + e.getMessage());
    }

    org.xipki.security.util.KeyUtil.addProviders();
  }

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
    Assume.assumeTrue("Can not generate secret key " + ckkCodeToName(keySpec.keyType()),
    keySpec.canGenerate(getToken()));
  }

  protected CkMechanism getSupportedMechanism(long mechCode, long flagBit) {
    return getSupportedMechanism(mechCode, flagBit, null);
  }

  protected CkMechanism getSupportedMechanism(
      long mechCode, long flagBit, CkParams parameters) {
    assertSupport(mechCode, flagBit);
    return new CkMechanism(mechCode, parameters);
  }

  protected PKCS11KeyId generateKeypair(PKCS11KeyPairType keyPairType, boolean inToken)
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
    } else if (keyType == CKK_DSA || keyType == CKK_ML_DSA || keyType == CKK_EC_EDWARDS) {
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
      throws InvalidKeySpecException, TokenException, NoSuchAlgorithmException {
    PKCS11Token token = getToken();
    if (keyType == null) {
      keyType = token.getAttrValues(p11Key, new AttributeTypes().keyType()).keyType();
    }

    if (keyType == CKK_RSA) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().modulus().publicExponent());
      KeySpec keySpec = new RSAPublicKeySpec(attrValues.modulus(), attrValues.publicExponent());
      return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } else if (keyType == CKK_DSA) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().value().prime().subprime().base()); // y, p, q, g

      DSAPublicKeySpec keySpec = new DSAPublicKeySpec( new BigInteger(1, attrValues.value()),
          attrValues.prime(), attrValues.subprime(), attrValues.base());
      return KeyFactory.getInstance("DSA").generatePublic(keySpec);
    } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS
        || keyType == CKK_EC_MONTGOMERY || keyType == CKK_VENDOR_SM2) {
      Template attrValues = token.getAttrValues(p11Key, new AttributeTypes().ecPoint().ecParams());
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
          throw new TokenException("unsupported ecParams " + Hex.encode(ecParams));
        }

        ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier(oidStr);

        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(algOid), encodedPoint);

        return KeyUtil.getPublicKey(pkInfo);
      } else {
        return createECPublicKey(ecParams, encodedPoint);
      }
    } else if (keyType == CKK_ML_DSA) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().parameterSet().value());

      byte[] value = attrValues.value();
      long variant = attrValues.parameterSet();

      ASN1ObjectIdentifier oid =
                (variant == CKP_ML_DSA_44) ? NISTObjectIdentifiers.id_ml_dsa_44
              : (variant == CKP_ML_DSA_65) ? NISTObjectIdentifiers.id_ml_dsa_65
              : NISTObjectIdentifiers.id_ml_dsa_87;

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), value);
      return KeyUtil.getPublicKey(pkInfo);
    } else if (keyType == CKK_ML_KEM) {
      Template attrValues = token.getAttrValues(p11Key,
          new AttributeTypes().value().parameterSet());
      byte[] value = attrValues.value();
      long variant = attrValues.parameterSet();

      ASN1ObjectIdentifier oid =
                (variant == CKP_ML_KEM_512) ? NISTObjectIdentifiers.id_alg_ml_kem_512
              : (variant == CKP_ML_KEM_768) ? NISTObjectIdentifiers.id_alg_ml_kem_768
              : NISTObjectIdentifiers.id_alg_ml_kem_1024;

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), value);
      return KeyUtil.getPublicKey(pkInfo);
    } else {
      throw new InvalidKeySpecException("unknown publicKey type " + ckkCodeToName(keyType));
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

  private static ECPublicKey createECPublicKey(
      byte[] encodedAlgorithmIdParameters, byte[] encodedPoint)
      throws InvalidKeySpecException {
    Args.notNull(encodedAlgorithmIdParameters, "encodedAlgorithmIdParameters");
    Args.notNull(encodedPoint, "encodedPoint");

    ASN1Encodable algParams;
    if (encodedAlgorithmIdParameters[0] == 6) {
      algParams = ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters);
    } else {
      algParams = X962Parameters.getInstance(encodedAlgorithmIdParameters);
    }
    AlgorithmIdentifier algId = new AlgorithmIdentifier(
        X9ObjectIdentifiers.id_ecPublicKey, algParams);

    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, encodedPoint);
    return (ECPublicKey) KeyUtil.getPublicKey(spki);
  }

}
