// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.ExtraParams;
import org.xipki.pkcs11.wrapper.PKCS11Key;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.security.KeySpec;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.LogUtil;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * PKCS#11 key.
 *
 * @author Lijun Liao (xipki)
 */
public class P11Key {

  private static final Logger LOG = LoggerFactory.getLogger(P11Key.class);

  final P11Slot slot;

  private final PKCS11Key key;

  private final EcCurveEnum ecParams;

  private final KeySpec keySpec;

  private boolean publicKeyInitialized;

  private PublicKey publicKey;

  public P11Key(P11Slot slot, PKCS11Key key) throws TokenException {
    this.slot = Args.notNull(slot, "slot");
    this.key = Args.notNull(key, "key");

    KeySpec keySpec = null;
    EcCurveEnum curve = null;

    PKCS11KeyId keyId = key.id();
    PKCS11KeyId.KeyIdType type = keyId.type();
    long keyType = keyId.getKeyType();

    if (key.rsaModulus() != null) {
      int bitLen = key.rsaModulus().bitLength();
      keySpec = KeySpec.ofRSA(bitLen);
    } else if (keyType == CKK_VENDOR_SM2) {
      curve = EcCurveEnum.SM2;
      keySpec = KeySpec.SM2;
    } else if (keyType == CKK_EC ||
        keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      byte[] ecParams = key.ecParams();
      if (ecParams == null && keyId.getPublicKeyHandle() != null) {
        if (type == PKCS11KeyId.KeyIdType.KEYPAIR || type == PKCS11KeyId.KeyIdType.PRIVATE_KEY) {
          // try the public key
          ecParams = slot.getAttrValues(keyId.getPublicKeyHandle(),
              new AttributeTypes().ecParams()).ecParams();
        }
      }

      if (ecParams != null) {
        curve = EcCurveEnum.ofEncodedOid(ecParams);
        keySpec = KeySpec.ofEcCurve(curve);
      }
    } else if (keyType == CKK_ML_DSA) {
      Long pqcVariant = key.pqcVariant();
      if (pqcVariant != null) {
        if (pqcVariant == CKP_ML_DSA_44) {
          keySpec = KeySpec.MLDSA44;
        } else if (pqcVariant == CKP_ML_DSA_65) {
          keySpec = KeySpec.MLDSA65;
        } else if (pqcVariant == CKP_ML_DSA_87) {
          keySpec = KeySpec.MLDSA87;
        }
      }
    } else if (keyType == CKK_ML_KEM) {
      Long pqcVariant = key.pqcVariant();
      if (pqcVariant != null) {
        if (pqcVariant == CKP_ML_KEM_512) {
          keySpec = KeySpec.MLKEM512;
        } else if (pqcVariant == CKP_ML_KEM_768) {
          keySpec = KeySpec.MLKEM768;
        } else if (pqcVariant == CKP_ML_KEM_1024) {
          keySpec = KeySpec.MLKEM1024;
        }
      }
    }

    this.keySpec = keySpec;
    this.ecParams = curve;
  }

  public void destroy() {
    slot.destroyObjectsAndReturnFailedHandles(key.id().getAllHandles());
  }

  public boolean isSign() {
    Boolean b = key.sign();
    return b != null && b;
  }

  public boolean isDecrypt() {
    Boolean b = key.decrypt();
    return b != null && b;
  }

  public boolean isDecapsulate() {
    Boolean b = key.decapsulate();
    return b != null && b;
  }

  public boolean isDerive() {
    Boolean b = key.derive();
    return b != null && b;
  }

  public EcCurveEnum ecParams() {
    return ecParams;
  }

  public KeySpec keySpec() {
    return keySpec;
  }

  /**
   * Signs the content.
   *
   * @param mechanism
   *          mechanism to sign the content.
   * @param parameters
   *          Parameters. Could be {@code null}.
   * @param content
   *          Content to be signed. Must not be {@code null}.
   * @return signature.
   * @throws TokenException
   *         if PKCS#11 token error occurs.
   */
  public byte[] sign(long mechanism, P11Params parameters, byte[] content) throws TokenException {
    Args.notNull(content, "content");

    if (!supportsSign(mechanism)) {
      throw new TokenException("this identity is not suitable for sign with "
          + PKCS11T.ckmCodeToName(mechanism));
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("sign with mechanism {}", PKCS11T.ckmCodeToName(mechanism));
    }

    ExtraParams extraParams = null;
    if (key.ecOrderBitSize() != null) {
      extraParams = new ExtraParams().ecOrderBitSize(key.ecOrderBitSize());
    }
    return slot.sign(mechanism, parameters, extraParams, key.id().getHandle(), content);
  }

  public byte[] decrypt(long mechanism, P11Params parameters, byte[] cipherText)
      throws TokenException {
    Args.notNull(cipherText, "cipherText");

    if (!supportsDecrypt(mechanism)) {
      throw new TokenException("this identity is not suitable for decrypt with "
          + PKCS11T.ckmCodeToName(mechanism));
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("decrypt with mechanism {}", PKCS11T.ckmCodeToName(mechanism));
    }

    return slot.decrypt(mechanism, parameters, key.id().getHandle(), cipherText);
  }

  public boolean supportsSign(long mechanism) {
    PKCS11KeyId keyId = key.id();
    return isSign()
        && (keyId.type() != PKCS11KeyId.KeyIdType.PUBLIC_KEY)
        && (keyId.getKeyType() != CKK_EC_MONTGOMERY && keyId.getKeyType() != CKK_ML_KEM)
        && slot.supportsMechanism(mechanism, CKF_SIGN);
  }

  public boolean supportsDecrypt(long mechanism) {
    PKCS11KeyId keyId = key.id();
    return isDecrypt()
        && (keyId.type() != PKCS11KeyId.KeyIdType.PUBLIC_KEY)
        && (keyId.getKeyType() != CKK_EC_EDWARDS && keyId.getKeyType() != CKK_ML_DSA)
        && slot.supportsMechanism(mechanism, CKF_DECRYPT);
  }

  public byte[] deriveKey(long mechanism, P11Params params, int keyByteSize)
      throws TokenException {
    Args.among(keyByteSize, "keyByteSize", 16, 24, 32);
    PKCS11SecretKeySpec template = new PKCS11SecretKeySpec().keyType(CKK_AES)
        .valueLen(keyByteSize).sensitive(false).extractable(true).token(false);
    long hNewKey = deriveKey(mechanism, params, template);
    return readValueAndDeleteKey(hNewKey, "derived key");
  }

  public long deriveKey(long mechanism, P11Params params, PKCS11SecretKeySpec template)
      throws TokenException {
    Args.notNull(template, "template");
    if (!supportsDerive(mechanism)) {
      throw new TokenException("this identity is not suitable for " +
          "deriveKey with " + PKCS11T.ckmCodeToName(mechanism));
    }

    return slot.deriveKey(mechanism, params, key.id().getHandle(), template);
  }

  public byte[] decapsulateKey(
      long mechanism, P11Params parameters, byte[] cipherText, int keyByteSize)
      throws TokenException {
    Args.among(keyByteSize, "keyByteSize", 16, 24, 32);
    PKCS11SecretKeySpec template = new PKCS11SecretKeySpec().keyType(CKK_AES)
        .valueLen(keyByteSize).sensitive(false).extractable(true).token(false);
    long hNewKey = decapsulateKey(mechanism, parameters, cipherText, template);
    return readValueAndDeleteKey(hNewKey, "decapsulate key");
  }

  private byte[] readValueAndDeleteKey(long hKey, String title) throws TokenException {
    try {
      byte[] newKeyValue = slot.getAttrValues(hKey, new AttributeTypes().value()).value();
      if (newKeyValue == null) {
        throw new TokenException("could not read CKA_VALUE of " + title);
      }
      return newKeyValue;
    } finally {
      slot.destroyObjectsAndReturnFailedHandles(hKey);
    }
  }

  public long decapsulateKey(long mechanism, P11Params parameters,
                            byte[] cipherText, PKCS11SecretKeySpec template)
      throws TokenException {
    Args.notNull(cipherText, "cipherText");

    if (!supportsDecapsulate(mechanism)) {
      throw new TokenException("this identity is not suitable for " +
          "decapsulateKey with " + PKCS11T.ckmCodeToName(mechanism));
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("decapsulateKey with mechanism {}", PKCS11T.ckmCodeToName(mechanism));
    }

    if (keySpec.isMlkem()) {
      template.valueLen(32);
    }

    if (template.keyType() == null) {
      template.keyType(CKK_AES);
    }

    return slot.decapsulateKey(mechanism, parameters, key.id().getHandle(), cipherText, template);
  }

  public boolean supportsDecapsulate(long mechanism) {
    PKCS11KeyId keyId = key.id();
    return isDecapsulate()
        && (keyId.type() != PKCS11KeyId.KeyIdType.PUBLIC_KEY)
        && (keyId.getKeyType() == CKK_ML_KEM)
        && slot.supportsMechanism(mechanism, CKF_DECAPSULATE);
  }

  public byte[] digestSecretKey(long mechanism) throws TokenException {
    if (!supportsDigest(mechanism)) {
      throw new TokenException("cannot digest this identity with " + ckmCodeToName(mechanism));
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("digest secret key with mechanism {}", ckmCodeToName(mechanism));
    }

    if (!isSecretKey()) {
      throw new TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    return slot.digestSecretKey(mechanism, key.id().getHandle());
  }

  public boolean supportsDigest(long mechanism) {
    return key.id().type() == PKCS11KeyId.KeyIdType.SECRET_KEY
        && slot.supportsMechanism(mechanism, CKF_DIGEST);
  }

  public boolean supportsDerive(long mechanism) {
    switch (key.id().type()) {
      case SECRET_KEY:
      case PRIVATE_KEY:
      case KEYPAIR:
        break;
      default:
        return false;
    }

    return slot.supportsMechanism(mechanism, CKF_DERIVE);
  }

  public P11SlotId slotId() {
    return slot.slotId();
  }

  public PKCS11Key key() {
    return key;
  }

  public boolean isSecretKey() {
    return key.id().type() == PKCS11KeyId.KeyIdType.SECRET_KEY;
  }

  public  PublicKey publicKey() {
    if (isSecretKey()) {
      return null;
    }

    if (publicKeyInitialized) {
      return publicKey;
    }

    try {
      this.publicKey = initPublicKey();
    } catch (Exception e) {
      LogUtil.error(LOG, e, "could not initialize public key for " +
          "(private) key " + key.id() + " on slot " + slot.slotId());
    } finally {
      publicKeyInitialized = true;
    }

    return publicKey;
  }

  private PublicKey initPublicKey() throws TokenException, InvalidKeySpecException {
    long keyType = key.id().getKeyType();
    if (keyType == CKK_RSA) {
      return KeyUtil.getRSAPublicKey(
          new RSAPublicKeySpec(key.rsaModulus(), key.rsaPublicExponent()));
    }

    Long publicKeyHandle = key.id().getPublicKeyHandle();
    if (publicKeyHandle == null) {
      return null;
    }

    if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
        || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      byte[] ecPoint = slot.getAttrValues(publicKeyHandle,
          new AttributeTypes().ecPoint()).ecPoint();

      if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        return KeyUtil.getPublicKey(new SubjectPublicKeyInfo(ecParams.algId(), ecPoint));
      } else {
        return KeyUtil.createECPublicKey(ecParams, ecPoint);
      }
    } else if (keyType == CKK_ML_DSA || keyType == CKK_ML_KEM) {
      Template attrs = slot.getAttrValues(publicKeyHandle,
          new AttributeTypes().parameterSet().value());
      Long variant = attrs.parameterSet();
      if (variant == null) {
        throw new TokenException("CKA_PARAMETER_SET is not present");
      }

      byte[] value = attrs.value();
      String oid = (keyType == CKK_ML_DSA) ? P11Slot.getStdMldsaOid(variant)
                    : P11Slot.getStdMlkemOid(variant);
      if (oid == null) {
        throw new TokenException("Invalid CKA_PARAMETER_SET " + variant);
      }

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
          new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)), value);
      return KeyUtil.getPublicKey(pkInfo);
    } else {
      throw new TokenException("unknown key type " + ckkCodeToName(keyType));
    }
  }

}
