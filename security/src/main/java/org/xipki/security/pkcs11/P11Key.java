// Copyright (c) 2013-2025 xipki. All rights reserved.
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
 * @since 2.0.0
 */

public class P11Key {

  private static final Logger LOG = LoggerFactory.getLogger(P11Key.class);

  private final P11Slot slot;

  private final PKCS11Key key;

  private EcCurveEnum ecParams;

  private Long parameterSet;

  private boolean publicKeyInitialized;

  private PublicKey publicKey;

  public P11Key(P11Slot slot, PKCS11Key key) {
    this.slot = Args.notNull(slot, "slot");
    this.key = Args.notNull(key, "key");
  }

  public void destroy() throws TokenException {
    slot.destroyObjectsAndReturnFailedHandles(key.id().getAllHandles());
  }

  public boolean isSign() {
    Boolean b = key.sign();
    return b != null && b;
  }

  public Long getParameterSet() {
    return parameterSet;
  }

  public void setParameterSet(Long parameterSet) {
    this.parameterSet = parameterSet;
  }

  public EcCurveEnum getEcParams() {
    return ecParams;
  }

  public void setEcParams(EcCurveEnum ecParams) {
    this.ecParams = ecParams;
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
  public byte[] sign(long mechanism, P11Params parameters, byte[] content)
      throws TokenException {
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
    return slot.sign(mechanism, parameters, extraParams, key.id().getHandle(),
        content);
  }

  public boolean supportsSign(long mechanism) {
    PKCS11KeyId keyId = key.id();
    return isSign()
        && (keyId.getType() != PKCS11KeyId.KeyIdType.PUBLIC_KEY)
        && (keyId.getKeyType() != CKK_EC_MONTGOMERY)
        && slot.supportsMechanism(mechanism, CKF_SIGN);
  }

  public byte[] digestSecretKey(long mechanism) throws TokenException {
    if (!supportsDigest(mechanism)) {
      throw new TokenException("cannot digest this identity with "
          + ckmCodeToName(mechanism));
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("digest secret key with mechanism {}",
          ckmCodeToName(mechanism));
    }

    if (!isSecretKey()) {
      throw new TokenException(
          "digestSecretKey could not be applied to non-SecretKey");
    }

    return slot.digestSecretKey(mechanism, key.id().getHandle());
  }

  public boolean supportsDigest(long mechanism) {
    return key.id().getType() == PKCS11KeyId.KeyIdType.SECRET_KEY
        && slot.supportsMechanism(mechanism, CKF_DIGEST);
  }

  public P11SlotId getSlotId() {
    return slot.getSlotId();
  }

  public PKCS11Key getKey() {
    return key;
  }

  public boolean isSecretKey() {
    return key.id().getType() == PKCS11KeyId.KeyIdType.SECRET_KEY;
  }

  public  PublicKey getPublicKey() {
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
          "(private) key " + key.id() + " on slot " + slot.getSlotId());
    } finally {
      publicKeyInitialized = true;
    }

    return publicKey;
  }

  private PublicKey initPublicKey()
      throws TokenException, InvalidKeySpecException {
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
        return KeyUtil.getPublicKey(
            new SubjectPublicKeyInfo(ecParams.getAlgId(), ecPoint));
      } else {
        return KeyUtil.createECPublicKey(ecParams, ecPoint);
      }
    } else if (keyType == CKK_ML_DSA) {
      Template attrs = slot.getAttrValues(publicKeyHandle,
          new AttributeTypes().parameterSet().value());
      Long variant = attrs.parameterSet();
      if (variant == null) {
        throw new TokenException("CKA_VENDOR_MLDSA_VARIANT is not present");
      }

      byte[] value = attrs.value();
      String oid = P11Slot.getStdMldsaOid(variant);
      if (oid == null) {
        throw new TokenException("Invalid CKA_VENDOR_MLDSA_VARIANT " + variant);
      }

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
          new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)), value);
      return KeyUtil.getPublicKey(pkInfo);
    } else {
      throw new TokenException("unknown key type " + ckkCodeToName(keyType));
    }
  }

}
