// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.attr;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public class XiTemplateChecker {

  private static final long[] storage_RO_Attrs = {
      CKA_CLASS, CKA_TOKEN};

  private static final long[] storage_RW_Attrs = {
      CKA_DESTROYABLE, CKA_PRIVATE, CKA_ID, CKA_MODIFIABLE, CKA_COPYABLE,
      CKA_DESTROYABLE, CKA_LABEL};

  private static final long[] data_RO_Attrs = storage_RO_Attrs;

  private static final long[] data_RW_Attrs =
      HsmUtil.concatenate(storage_RW_Attrs,
          CKA_APPLICATION, CKA_VALUE, CKA_OBJECT_ID);

  private static final long[] cert_RO_Attrs =
      HsmUtil.concatenate(storage_RO_Attrs,
          CKA_CERTIFICATE_TYPE, CKA_CERTIFICATE_CATEGORY);

  private static final long[] cert_RW_Attrs =
      HsmUtil.concatenate(storage_RW_Attrs,
          CKA_TRUSTED, CKA_CHECK_VALUE,
          CKA_PUBLIC_KEY_INFO, CKA_START_DATE, CKA_END_DATE);

  private static final long[] x509Cert_RO_Attrs =
      HsmUtil.concatenate(cert_RO_Attrs,
          CKA_VALUE, CKA_URL);

  private static final long[] x509Cert_RW_Attrs =
      HsmUtil.concatenate(cert_RW_Attrs,
          CKA_ID, CKA_ISSUER, CKA_SUBJECT, CKA_SERIAL_NUMBER,
          CKA_HASH_OF_ISSUER_PUBLIC_KEY, CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
          CKA_JAVA_MIDP_SECURITY_DOMAIN, CKA_NAME_HASH_ALGORITHM);

  private static final long[] key_RO_Attrs =
      HsmUtil.concatenate(storage_RO_Attrs,
          CKA_KEY_TYPE, CKA_KEY_GEN_MECHANISM);

  private static final long[] key_RW_Attrs =
      HsmUtil.concatenate(storage_RW_Attrs,
          CKA_ID, CKA_START_DATE, CKA_END_DATE,
          CKA_DERIVE, CKA_LOCAL, CKA_ALLOWED_MECHANISMS);

  private static final long[] privateOrSecretKey_RO_Attrs =
      HsmUtil.concatenate(key_RO_Attrs,
          CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE);

  private static final long[] privateOrSecretKey_RW_Attrs =
      HsmUtil.concatenate(key_RW_Attrs,
          CKA_DECRYPT, CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_SIGN,
          CKA_UNWRAP,  CKA_WRAP_WITH_TRUSTED, CKA_UNWRAP_TEMPLATE,
          CKA_DERIVE_TEMPLATE);

  private static final long[] privateKey_RO_Attrs =
      privateOrSecretKey_RO_Attrs;

  private static final long[] privateKey_RW_Attrs =
      HsmUtil.concatenate(privateOrSecretKey_RW_Attrs,
          CKA_SUBJECT, CKA_SIGN_RECOVER, CKA_ALWAYS_AUTHENTICATE,
          CKA_PUBLIC_KEY_INFO, CKA_DECAPSULATE, CKA_DECAPSULATE_TEMPLATE);

  private static final long[] publicKey_RO_Attrs = key_RO_Attrs;

  private static final long[] publicKey_RW_Attrs = HsmUtil.concatenate(
      key_RW_Attrs,
      CKA_SUBJECT, CKA_ENCRYPT, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP,
      CKA_SUBJECT, CKA_WRAP_TEMPLATE, CKA_PUBLIC_KEY_INFO,
      CKA_ENCAPSULATE, CKA_ENCAPSULATE_TEMPLATE);

  // secret key
  private static final long[] secretKey_RO_Attrs =
      HsmUtil.concatenate(privateOrSecretKey_RO_Attrs,
          CKA_VALUE, CKA_VALUE_LEN);

  private static final long[] secretKey_RW_Attrs =
      HsmUtil.concatenate(privateOrSecretKey_RW_Attrs,
          CKA_ENCRYPT, CKA_VERIFY, CKA_WRAP, CKA_TRUSTED,
          CKA_WRAP_TEMPLATE, CKA_CHECK_VALUE);

  // EC key
  private static final long[] ecPrivateKey_RO_Attrs =
      HsmUtil.concatenate(privateKey_RO_Attrs,
          CKA_EC_PARAMS, CKA_EC_POINT, CKA_VALUE);

  private static final long[] ecPublicKey_RO_Attrs =
      HsmUtil.concatenate(publicKey_RO_Attrs,
          CKA_EC_PARAMS, CKA_EC_POINT);

  // RSA key
  private static final long[] rsaPrivateKey_RO_Attrs =
      HsmUtil.concatenate(privateKey_RO_Attrs,
          CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_PRIVATE_EXPONENT, CKA_PRIME_1,
          CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT);

  private static final long[] rsaPublicKey_RO_Attrs =
      HsmUtil.concatenate(
          publicKey_RO_Attrs,
          CKA_MODULUS, CKA_PUBLIC_EXPONENT);

  // ML-DSA key
  private static final long[] mldsaPrivateKey_RO_Attrs =
      HsmUtil.concatenate(
          privateKey_RO_Attrs, CKA_PARAMETER_SET, CKA_VALUE);

  private static final long[] mldsaPublicKey_RO_Attrs =
      HsmUtil.concatenate(publicKey_RO_Attrs, CKA_PARAMETER_SET, CKA_VALUE);

  // ML-KEM key
  private static final long[] mlkemPrivateKey_RO_Attrs =
      HsmUtil.concatenate(privateKey_RO_Attrs, CKA_PARAMETER_SET, CKA_VALUE);

  private static final long[] mlkemPublicKey_RO_Attrs =
      HsmUtil.concatenate(publicKey_RO_Attrs, CKA_PARAMETER_SET, CKA_VALUE);

  public static void assertSecretKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        secretKey_RO_Attrs, secretKey_RW_Attrs);
  }

  public static void assertRsaPrivateKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        rsaPrivateKey_RO_Attrs, privateKey_RW_Attrs);
  }

  public static void assertRsaPublicKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        rsaPublicKey_RO_Attrs, publicKey_RW_Attrs);
  }

  public static void assertEcPrivateKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        ecPrivateKey_RO_Attrs, privateKey_RW_Attrs);
  }

  public static void assertEcPublicKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        ecPublicKey_RO_Attrs, publicKey_RW_Attrs);
  }

  public static void assertMldsaPrivateKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        mldsaPrivateKey_RO_Attrs, privateKey_RW_Attrs);
  }

  public static void assertMldsaPublicKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        mldsaPublicKey_RO_Attrs, publicKey_RW_Attrs);
  }

  public static void assertMlkemPrivateKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        mlkemPrivateKey_RO_Attrs, privateKey_RW_Attrs);
  }

  public static void assertMlkemPublicKeyAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        mlkemPublicKey_RO_Attrs, publicKey_RW_Attrs);
  }

  public static void assertDataAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs, data_RO_Attrs, data_RW_Attrs);
  }

  public static void assertX509CertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    assertSecretKeyAttributesSettable(attrs,
        x509Cert_RO_Attrs, x509Cert_RW_Attrs);
  }

  private static void assertSecretKeyAttributesSettable(
      XiTemplate attrs, long[] roTypes, long[] rwTypes)
      throws HsmException {
    for (long type : attrs.getTypes()) {
      if (HsmUtil.contains(roTypes, type)) {
        throw new HsmException(CKR_ATTRIBUTE_READ_ONLY,
            "Attribute " + PKCS11T.ckaCodeToName(type) +
            " is read-only");
      }

      if (!HsmUtil.contains(rwTypes, type)) {
        throw new HsmException(CKR_ATTRIBUTE_TYPE_INVALID,
            "Attribute " + PKCS11T.ckaCodeToName(type) +
            " is not allowed");
      }
    }
  }

}
