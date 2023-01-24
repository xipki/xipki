/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.XiSecurityException;
import org.xipki.util.LogUtil;

import java.math.BigInteger;
import java.security.PublicKey;

import static org.xipki.pkcs11.PKCS11Constants.*;
import static org.xipki.util.Args.notNull;

/**
 * PKCS#11 identity (private key and the corresponding public key and certificates).
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11Identity implements Comparable<P11Identity> {

  private static final Logger LOG = LoggerFactory.getLogger(P11Identity.class);

  protected final P11Slot slot;

  protected final P11IdentityId id;

  private int expectedSignatureLen;

  private ASN1ObjectIdentifier ecParams;

  private BigInteger rsaModulus;

  private BigInteger rsaPublicExponent;

  private BigInteger dsaQ;

  private boolean publicKeyInitialized;

  private PublicKey publicKey;

  protected P11Identity(P11Slot slot, P11IdentityId id) {
    this.slot = notNull(slot, "slot");
    this.id = notNull(id, "id");
  }

  public abstract void destroy() throws P11TokenException;

  public ASN1ObjectIdentifier getEcParams() {
    return ecParams;
  }

  public void setEcParams(ASN1ObjectIdentifier ecParams) {
    if (EdECConstants.id_ED25519.equals(ecParams)) {
      expectedSignatureLen = 64;
    } else if (EdECConstants.id_ED448.equals(ecParams)) {
      expectedSignatureLen = 114;
    } else {
      X9ECParameters x9params = ECUtil.getNamedCurveByOid(ecParams);
      if (x9params != null) {
        expectedSignatureLen = (x9params.getCurve().getOrder().bitLength() + 7) / 8 * 2;
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
    expectedSignatureLen = (modulus.bitLength() + 7) / 8;
  }

  public BigInteger getDsaQ() {
    return dsaQ;
  }

  public void setDsaQ(BigInteger q) {
    this.dsaQ = q;
    expectedSignatureLen = (q.bitLength() + 7) / 8 * 2;
  }

  public byte[] sign(long mechanism, P11Params parameters, byte[] content) throws P11TokenException {
    if (id.getKeyId().getKeyType() == CKK_EC_MONTGOMERY) {
      throw new P11TokenException("this identity is not suitable for sign");
    }

    notNull(content, "content");
    slot.assertMechanismSupported(mechanism);
    if (!supportsMechanism(mechanism, parameters)) {
      throw new P11UnsupportedMechanismException(mechanism, id);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("sign with mechanism {}", ckmCodeToName(mechanism));
    }
    return sign0(mechanism, parameters, content);
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
   * @throws P11TokenException
   *         if PKCS#11 token error occurs.
   */
  protected abstract byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException;

  public byte[] digestSecretKey(long mechanism) throws P11TokenException, XiSecurityException {
    slot.assertMechanismSupported(mechanism);
    if (LOG.isDebugEnabled()) {
      LOG.debug("digest secret with mechanism {}", ckmCodeToName(mechanism));
    }
    return digestSecretKey0(mechanism);
  }

  protected abstract byte[] digestSecretKey0(long mechanism) throws P11TokenException;

  public P11IdentityId getId() {
    return id;
  }

  public long getKeyType() {
    return id.getKeyId().getKeyType();
  }

  public int getExpectedSignatureLen() {
    return expectedSignatureLen;
  }

  public void setExpectedSignatureLen(int numBytes) {
    this.expectedSignatureLen = numBytes;
  }

  public boolean match(P11IdentityId id) {
    return this.id.equals(id);
  }

  public boolean match(P11SlotId slotId, String keyLabel) {
    return id.match(slotId, keyLabel);
  }

  @Override
  public int compareTo(P11Identity obj) {
    return id.compareTo(obj.id);
  }

  public boolean isSecretKey() {
    return id.getKeyId().getObjectCLass() == CKO_SECRET_KEY;
  }

  public final synchronized PublicKey getPublicKey() {
    if (isSecretKey()) {
      return null;
    }

    if (publicKeyInitialized) {
      return publicKey;
    } else {
      try {
        publicKey = slot.getPublicKey(this);
      } catch (Exception e) {
        LogUtil.error(LOG, e, "could not initialize public key for (private) key " + id);
      } finally {
        publicKeyInitialized = true;
      }
      return publicKey;
    }
  }

  public boolean supportsMechanism(long mechanism) {
    return slot.supportsMechanism(mechanism);
  }

  public boolean supportsMechanism(long mechanism, P11Params parameters) {
    if (!supportsMechanism(mechanism)) {
      return false;
    }

    if (isSecretKey()) {
      if (CKM_SHA_1_HMAC == mechanism
          || CKM_SHA224_HMAC == mechanism   || CKM_SHA256_HMAC == mechanism
          || CKM_SHA384_HMAC == mechanism   || CKM_SHA512_HMAC == mechanism
          || CKM_SHA3_224_HMAC == mechanism || CKM_SHA3_256_HMAC == mechanism
          || CKM_SHA3_384_HMAC == mechanism || CKM_SHA3_512_HMAC == mechanism) {
        return parameters == null;
      }
    }

    long keyType = getKeyType();
    if (keyType == CKK_RSA) {
      if (CKM_RSA_9796 == mechanism || CKM_RSA_PKCS == mechanism
          || CKM_SHA1_RSA_PKCS == mechanism   || CKM_SHA224_RSA_PKCS == mechanism
          || CKM_SHA256_RSA_PKCS == mechanism || CKM_SHA384_RSA_PKCS == mechanism
          || CKM_SHA512_RSA_PKCS == mechanism) {
        return parameters == null;
      } else if (CKM_RSA_PKCS_PSS == mechanism
          || CKM_SHA1_RSA_PKCS_PSS == mechanism   || CKM_SHA224_RSA_PKCS_PSS == mechanism
          || CKM_SHA256_RSA_PKCS_PSS == mechanism || CKM_SHA384_RSA_PKCS_PSS == mechanism
          || CKM_SHA512_RSA_PKCS_PSS == mechanism) {
        return parameters instanceof P11Params.P11RSAPkcsPssParams;
      } else if (CKM_RSA_X_509 == mechanism) {
        return parameters == null;
      }
    } else if (keyType == CKK_DSA) {
      if (parameters != null) {
        return false;
      }
      return CKM_DSA == mechanism || CKM_DSA_SHA1 == mechanism
          || CKM_DSA_SHA224 == mechanism || CKM_DSA_SHA256 == mechanism
          || CKM_DSA_SHA384 == mechanism || CKM_DSA_SHA512 == mechanism;
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2) {
      if (CKM_ECDSA == mechanism || CKM_ECDSA_SHA1 == mechanism
          || CKM_ECDSA_SHA224 == mechanism || CKM_ECDSA_SHA256 == mechanism
          || CKM_ECDSA_SHA384 == mechanism || CKM_ECDSA_SHA512 == mechanism
          || CKM_VENDOR_SM2 == mechanism) {
        return parameters == null;
      } else if (CKM_VENDOR_SM2_SM3 == mechanism) {
        return parameters instanceof P11Params.P11ByteArrayParams;
      }
    } else if (keyType == CKK_EC_EDWARDS) {
      return CKM_EDDSA == mechanism;
    }

    return false;
  } // method supportsMechanism

}
