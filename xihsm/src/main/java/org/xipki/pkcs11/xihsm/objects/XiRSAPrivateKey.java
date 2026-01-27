// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.BigIntegers;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_PSS_PARAMS;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.crypt.HashAlgo;
import org.xipki.pkcs11.xihsm.crypt.PKCS1Util;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public class XiRSAPrivateKey extends XiPrivateKey {

  /**
   * Modulus n.
   * <p>
   * MUST be specified when object is created with C_CreateObject
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   */
  private final BigInteger modulus; // n

  /**
   * Public exponent e
   * <p>
   * MUST be specified when object is created with C_CreateObject
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   */
  private final BigInteger publicExponent; // e

  /**
   * Private exponent d
   * <p>
   * MUST be specified when object is created with C_CreateObject
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   * <p>
   * Cannot be revealed if object has its CKA_SENSITIVE attribute set to
   * CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE.
   */
  private final BigInteger privateExponent; // d

  /**
   * Prime p, CKA_PRIME_1.
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   * <p>
   * Cannot be revealed if object has its CKA_SENSITIVE attribute set to
   * CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE.
   */
  private final BigInteger p; // prime1

  /**
   * Prime 1, CKA_PRIME_2.
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   * <p>
   * Cannot be revealed if object has its CKA_SENSITIVE attribute set to
   * CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE.
   */
  private final BigInteger q; // prime2

  /**
   * Private exponent d modulo p-1. CKA_EXPONENT_1
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   * <p>
   * Cannot be revealed if object has its CKA_SENSITIVE attribute set to
   * CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE.
   */
  private final BigInteger dP; // exponent 1

  /**
   * Private exponent d modulo q-1. CKA_EXPONENT_2
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   * <p>
   * Cannot be revealed if object has its CKA_SENSITIVE attribute set to
   * CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE.
   */
  private final BigInteger dQ; // exponent 2

  /**
   * CRT coefficient q^(-1) mod p. CKA_COEFFICIENT.
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   * <p>
   * Cannot be revealed if object has its CKA_SENSITIVE attribute set to
   * CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE.
   */
  private final BigInteger qInv; // co-efficient

  private final int modulusBitSize;

  public XiRSAPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod
      , long handle, boolean inToken, Long keyGenMechanism,
      BigInteger modulus, BigInteger publicExponent,
      BigInteger privateExponent, BigInteger p, BigInteger q,
      BigInteger dP, BigInteger dQ, BigInteger qInv) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_RSA, keyGenMechanism);
    this.modulus = Args.notNull(modulus, "modulus");
    this.publicExponent  = Args.notNull(publicExponent, "publicExponent");
    this.privateExponent = Args.notNull(privateExponent, "privateExponent");
    this.p    = Args.notNull(p, "p");
    this.q    = Args.notNull(q, "q");
    this.dP   = Args.notNull(dP, "dP");
    this.dQ   = Args.notNull(dQ, "dQ");
    this.qInv = Args.notNull(qInv, "qInv");
    this.modulusBitSize = modulus.bitLength();
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    XiTemplateChecker.assertRsaPrivateKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, CKA_MODULUS, modulus);
    addAttr(res, types, CKA_PUBLIC_EXPONENT, publicExponent);

    if (withAll || !isSensitive()) {
      addAttr(res, types, CKA_PRIVATE_EXPONENT, privateExponent);
      addAttr(res, types, CKA_PRIME_1,     p);
      addAttr(res, types, CKA_PRIME_2,     q);
      addAttr(res, types, CKA_EXPONENT_1,  dP);
      addAttr(res, types, CKA_EXPONENT_2,  dQ);
      addAttr(res, types, CKA_COEFFICIENT, qInv);
    }
  }

  private byte[] decryptRaw(byte[] em) throws HsmException {
    if (em.length * 8 != modulusBitSize) {
      throw new HsmException(CKR_GENERAL_ERROR,
          "em.length != " + (modulusBitSize / 8) + ": " + em.length);
    }

    BigInteger m = new BigInteger(1, em);
    BigInteger m1 = m.modPow(dP, p);
    BigInteger m2 = m.modPow(dQ, q);

    BigInteger m1_m2 = m1.subtract(m2).mod(p);
    if (m1_m2.signum() < 0) {
      m1_m2 = m1_m2.add(p);
    }
    BigInteger h = qInv.multiply(m1_m2).mod(p);
    BigInteger c = m2.add(h.multiply(q));

    return BigIntegers.asUnsignedByteArray(em.length, c);
  }

  @Override
  public byte[] getEncoded() throws HsmException {
    org.bouncycastle.asn1.pkcs.RSAPrivateKey asn1Key =
        new org.bouncycastle.asn1.pkcs.RSAPrivateKey(modulus,
            publicExponent, privateExponent, p, q, dP, dQ, qInv);

    try {
      return new PrivateKeyInfo(
          new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
              DERNull.INSTANCE), asn1Key).getEncoded();
    } catch (IOException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error encoding " + getClass().getName(), ex);
    }
  }

  @Override
  public byte[] sign(XiMechanism mechanism, byte[] data, SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
          "CKA_SIGN != TRUE");
    }

    long ckm = mechanism.getCkm();
    Object param = mechanism.getParameter();

    if (ckm == CKM_RSA_PKCS
        || ckm == CKM_SHA256_RSA_PKCS
        || ckm == CKM_SHA384_RSA_PKCS
        || ckm == CKM_SHA512_RSA_PKCS) {
      HsmUtil.assertNullParameter(mechanism);
      if (ckm == CKM_RSA_PKCS) {
        byte[] em;
        try {
          em = PKCS1Util.EMSA_PKCS1_v1_5_encode(data, modulusBitSize);
        } catch (Exception e) {
          throw new HsmException(CKR_GENERAL_ERROR,
              "EMSA_PKCS1_v1_5_encode error", e);
        }

        return decryptRaw(em);
      } else {
        HashAlgo hashAlgo = extractPkcs1v1d5HashAlgo(ckm);
        byte[] hash = hashAlgo.hash(data);

        byte[] em;
        try {
          em = PKCS1Util.EMSA_PKCS1_v1_5_encode(hash, modulusBitSize, hashAlgo);
        } catch (Exception e) {
          throw new HsmException(CKR_GENERAL_ERROR,
              "EMSA_PKCS1_v1_5_encode error", e);
        }

        return decryptRaw(em);
      }
    } else if (ckm == CKM_RSA_PKCS_PSS
        || ckm == CKM_SHA256_RSA_PKCS_PSS
        || ckm == CKM_SHA384_RSA_PKCS_PSS
        || ckm == CKM_SHA512_RSA_PKCS_PSS) {
      if (!(param instanceof RSA_PKCS_PSS_PARAMS)) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
            "Mechanism.parameters is not CK_RSA_PKCS_PSS_PARAMS");
      }

      RSA_PKCS_PSS_PARAMS p = (RSA_PKCS_PSS_PARAMS) param;
      int saltLen = (int) p.sLen();
      HashAlgo hashAlgo = extractHashAlgo(ckm, p);

      byte[] hashValue;
      if (ckm == CKM_RSA_PKCS_PSS) {
        hashValue = data;
      } else {
        hashValue = hashAlgo.hash(data);
      }

      byte[] em;
      try {
        em = PKCS1Util.EMSA_PSS_ENCODE(hashAlgo, hashValue, hashAlgo,
            saltLen, modulusBitSize, random);
      } catch (Exception e) {
        throw new HsmException(CKR_GENERAL_ERROR,
            "EMSA_PSS_ENCODE error", e);
      }

      return decryptRaw(em);
    } else {
      throw new HsmException(CKR_MECHANISM_INVALID,
          "Invalid mechanism " + PKCS11T.ckmCodeToName(ckm));
    }
  }

  static HashAlgo extractPkcs1v1d5HashAlgo(long mechanism) {
    HashAlgo hashAlgo;
    if (mechanism == CKM_SHA1_RSA_PKCS) {
      hashAlgo = HashAlgo.SHA1;
    } else if (mechanism == CKM_SHA224_RSA_PKCS) {
      hashAlgo = HashAlgo.SHA224;
    } else if (mechanism == CKM_SHA256_RSA_PKCS) {
      hashAlgo = HashAlgo.SHA256;
    } else if (mechanism == CKM_SHA384_RSA_PKCS) {
      hashAlgo = HashAlgo.SHA384;
    } else if (mechanism == CKM_SHA512_RSA_PKCS) {
      hashAlgo = HashAlgo.SHA512;
    } else {
      hashAlgo = null;
    }
    return hashAlgo;
  }

  static HashAlgo extractHashAlgo(
      long mechanism, RSA_PKCS_PSS_PARAMS params)
      throws HsmException {
    long hashAlg = params.hashAlg();
    long mgf = params.mgf();

    HashAlgo hashAlgo = null;
    if (mechanism == CKM_SHA1_RSA_PKCS_PSS) {
      if (hashAlg == CKM_SHA_1 && mgf == CKG_MGF1_SHA1) {
        hashAlgo = HashAlgo.SHA1;
      }
    } else if (mechanism == CKM_SHA224_RSA_PKCS_PSS) {
      if (hashAlg == CKM_SHA224 && mgf == CKG_MGF1_SHA224) {
        hashAlgo = HashAlgo.SHA224;
      }
    } else if (mechanism == CKM_SHA256_RSA_PKCS_PSS) {
      if (hashAlg == CKM_SHA256 && mgf == CKG_MGF1_SHA256) {
        hashAlgo = HashAlgo.SHA256;
      }
    } else if (mechanism == CKM_SHA384_RSA_PKCS_PSS) {
      if (hashAlg == CKM_SHA384 && mgf == CKG_MGF1_SHA384) {
        hashAlgo = HashAlgo.SHA384;
      }
    } else if (mechanism == CKM_SHA512_RSA_PKCS_PSS) {
      if (hashAlg == CKM_SHA512 && mgf == CKG_MGF1_SHA512) {
        hashAlgo = HashAlgo.SHA512;
      }
    } else if (mechanism == CKM_RSA_PKCS_PSS
        || mechanism == CKM_RSA_PKCS_OAEP) {
      if (hashAlg == CKM_SHA_1) {
        if (mgf == CKG_MGF1_SHA1) {
          hashAlgo = HashAlgo.SHA1;
        }
      } else if (hashAlg == CKM_SHA224) {
        if (mgf == CKG_MGF1_SHA224) {
          hashAlgo = HashAlgo.SHA224;
        }
      } else if (hashAlg == CKM_SHA256) {
        if (mgf == CKG_MGF1_SHA256) {
          hashAlgo = HashAlgo.SHA256;
        }
      } else if (hashAlg == CKM_SHA384) {
        if (mgf == CKG_MGF1_SHA384) {
          hashAlgo = HashAlgo.SHA384;
        }
      } else if (hashAlg == CKM_SHA512) {
        if (mgf == CKG_MGF1_SHA512) {
          hashAlgo = HashAlgo.SHA512;
        }
      }
    }

    if (hashAlgo == null) {
      throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
          "Unsupported " + params.getClass().getSimpleName());
    }

    return hashAlgo;
  }

  public static XiRSAPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    BigInteger modulus = attrs.removeNonNullBigInt(CKA_MODULUS);
    BigInteger publicExponent  = attrs.removeNonNullBigInt(CKA_PUBLIC_EXPONENT);
    BigInteger privateExponent =
        attrs.removeNonNullBigInt(CKA_PRIVATE_EXPONENT);
    BigInteger p    = attrs.removeNonNullBigInt(CKA_PRIME_1);
    BigInteger q    = attrs.removeNonNullBigInt(CKA_PRIME_2);
    BigInteger dP   = attrs.removeNonNullBigInt(CKA_EXPONENT_1);
    BigInteger dQ   = attrs.removeNonNullBigInt(CKA_EXPONENT_2);
    BigInteger qInv = attrs.removeNonNullBigInt(CKA_COEFFICIENT);

    XiRSAPrivateKey ret = new XiRSAPrivateKey(vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, modulus,
        publicExponent, privateExponent, p, q, dP, dQ, qInv);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
