// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_DIGEST;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC_MONTGOMERY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKO_PUBLIC_KEY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKO_SECRET_KEY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckmCodeToName;

/**
 * PKCS#11 key.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class P11Key {

  private static final Logger LOG = LoggerFactory.getLogger(P11Key.class);

  protected final P11Slot slot;

  protected final PKCS11KeyId keyId;

  private boolean sign;

  protected ASN1ObjectIdentifier ecParams;

  protected Integer ecOrderBitSize;

  protected BigInteger rsaModulus;

  protected BigInteger rsaPublicExponent;

  protected BigInteger dsaP;

  protected BigInteger dsaQ;

  protected BigInteger dsaG;

  private boolean publicKeyInitialized;

  private PublicKey publicKey;

  protected P11Key(P11Slot slot, PKCS11KeyId keyId) {
    this.slot = Args.notNull(slot, "slot");
    this.keyId = Args.notNull(keyId, "keyId");
  }

  public P11Key sign(Boolean sign) {
    this.sign = sign == null || sign;
    return this;
  }

  public abstract void destroy() throws TokenException;

  public boolean isSign() {
    return sign;
  }

  public ASN1ObjectIdentifier getEcParams() {
    return ecParams;
  }

  public Integer getEcOrderBitSize() {
    return ecOrderBitSize;
  }

  public void setEcParams(ASN1ObjectIdentifier ecParams) {
    if (ecParams == null) {
      this.ecOrderBitSize = null;
    } else {
      try {
        this.ecOrderBitSize = Functions.getCurveOrderBitLength(ecParams.getEncoded());
      } catch (IOException e) {
      }
    }
    this.ecParams = ecParams;
  }

  public BigInteger getRsaModulus() {
    return rsaModulus;
  }

  public BigInteger getRsaPublicExponent() {
    return rsaPublicExponent;
  }

  public void setRsaMParameters(BigInteger modulus, BigInteger publicExponent) {
    this.rsaModulus = modulus;
    this.rsaPublicExponent = publicExponent;
  }

  public BigInteger getDsaP() {
    return dsaP;
  }

  public BigInteger getDsaQ() {
    return dsaQ;
  }

  public BigInteger getDsaG() {
    return dsaG;
  }

  public void setDsaParameters(BigInteger p, BigInteger q, BigInteger g) {
    this.dsaP = p;
    this.dsaQ = q;
    this.dsaG = g;
  }

  public byte[] sign(long mechanism, P11Params parameters, byte[] content) throws TokenException {
    Args.notNull(content, "content");

    if (!supportsSign(mechanism)) {
      throw new TokenException("this identity is not suitable for sign with " + ckmCodeToName(mechanism));
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("sign with mechanism {}", ckmCodeToName(mechanism));
    }
    return sign0(mechanism, parameters, content);
  }

  public boolean supportsSign(long mechanism) {
    return sign && (keyId.getObjectCLass() != CKO_PUBLIC_KEY)
        && (keyId.getKeyType() != CKK_EC_MONTGOMERY) && slot.supportsMechanism(mechanism, CKF_SIGN);
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
  protected abstract byte[] sign0(long mechanism, P11Params parameters, byte[] content) throws TokenException;

  public byte[] digestSecretKey(long mechanism) throws TokenException {
    if (!supportsDigest(mechanism)) {
      throw new TokenException("cannot digest this identity with " + ckmCodeToName(mechanism));
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("digest secret key with mechanism {}", ckmCodeToName(mechanism));
    }
    return digestSecretKey0(mechanism);
  }

  public boolean supportsDigest(long mechanism) {
    return keyId.getObjectCLass() == CKO_SECRET_KEY && slot.supportsMechanism(mechanism, CKF_DIGEST);
  }

  protected abstract byte[] digestSecretKey0(long mechanism) throws TokenException;

  protected abstract PublicKey getPublicKey0() throws TokenException;

  public P11SlotId getSlotId() {
    return slot.getSlotId();
  }

  public PKCS11KeyId getKeyId() {
    return keyId;
  }

  public long getKeyType() {
    return keyId.getKeyType();
  }

  public boolean isSecretKey() {
    return keyId.getObjectCLass() == CKO_SECRET_KEY;
  }

  public  PublicKey getPublicKey() {
    if (isSecretKey()) {
      return null;
    }

    if (publicKeyInitialized) {
      return publicKey;
    }

    try {
      publicKey = getPublicKey0();
    } catch (Exception e) {
      LogUtil.error(LOG, e, "could not initialize public key for (private) key " + keyId
          + " on slot " + slot.getSlotId());
    } finally {
      publicKeyInitialized = true;
    }

    return publicKey;
  }

}
