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

import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.util.CollectionUtil;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

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

  protected final PublicKey publicKey;

  private final int signatureKeyBitLength;

  protected X509Cert[] certificateChain;

  protected P11Identity(P11Slot slot, P11IdentityId id, int signatureBitLen) {
    this.slot = notNull(slot, "slot");
    this.id = notNull(id, "id");
    this.publicKey = null;
    this.signatureKeyBitLength = signatureBitLen;
  } // constructor

  protected P11Identity(P11Slot slot, P11IdentityId id, PublicKey publicKey,
      X509Cert[] certificateChain) {
    this.slot = notNull(slot, "slot");
    this.id = notNull(id, "id");

    if (certificateChain != null && certificateChain.length > 0 && certificateChain[0] != null) {
      this.publicKey = certificateChain[0].getPublicKey();
      this.certificateChain = certificateChain;
    } else if (publicKey != null) {
      this.publicKey = publicKey;
      this.certificateChain = null;
    } else {
      throw new IllegalArgumentException("neither certificate nor publicKey is non-null");
    }

    if (this.publicKey instanceof RSAPublicKey) {
      signatureKeyBitLength = ((RSAPublicKey) this.publicKey).getModulus().bitLength();
    } else if (this.publicKey instanceof ECPublicKey) {
      signatureKeyBitLength = ((ECPublicKey) this.publicKey).getParams().getOrder()
          .bitLength();
    } else if (this.publicKey instanceof DSAPublicKey) {
      signatureKeyBitLength = ((DSAPublicKey) this.publicKey).getParams().getQ().bitLength();
    } else if (this.publicKey instanceof EdDSAKey) {
      // will not be used
      signatureKeyBitLength = 0;
    } else if (this.publicKey instanceof XDHKey) {
      // no signature is supported
      signatureKeyBitLength = 0;
    } else {
      throw new IllegalArgumentException("currently only RSA, DSA, EC and Edwards public key are "
          + "supported, but not " + this.publicKey.getAlgorithm() + " (class: "
          + this.publicKey.getClass().getName() + ")");
    }
  } // constructor

  public byte[] sign(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    if (publicKey instanceof XDHKey) {
      throw new P11TokenException("this identity is not suitable for sign");
    }

    notNull(content, "content");
    slot.assertMechanismSupported(mechanism);
    if (!supportsMechanism(mechanism, parameters)) {
      throw new P11UnsupportedMechanismException(mechanism, id);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("sign with mechanism {}", Functions.getMechanismDescription(mechanism));
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

  public byte[] digestSecretKey(long mechanism)
      throws P11TokenException, XiSecurityException {
    slot.assertMechanismSupported(mechanism);
    if (LOG.isDebugEnabled()) {
      LOG.debug("digest secret with mechanism {}", Functions.getMechanismDescription(mechanism));
    }
    return digestSecretKey0(mechanism);
  }

  protected abstract byte[] digestSecretKey0(long mechanism)
      throws P11TokenException;

  public P11IdentityId getId() {
    return id;
  }

  public X509Cert getCertificate() {
    return (certificateChain != null && certificateChain.length > 0) ? certificateChain[0] : null;
  }

  public X509Cert[] certificateChain() {
    return (certificateChain == null) ? null
        : Arrays.copyOf(certificateChain, certificateChain.length);
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public void setCertificates(X509Cert[] certificateChain)
      throws P11TokenException {
    if (CollectionUtil.isEmpty(certificateChain)) {
      this.certificateChain = null;
    } else {
      PublicKey pk = certificateChain[0].getPublicKey();
      if (!this.publicKey.equals(pk)) {
        throw new P11TokenException("certificateChain is not for the key");
      }
      this.certificateChain = certificateChain;
    }
  }

  public boolean match(P11IdentityId id) {
    return this.id.equals(id);
  }

  public boolean match(P11SlotIdentifier slotId, String keyLabel) {
    return id.match(slotId, keyLabel);
  }

  public int getSignatureKeyBitLength() {
    return signatureKeyBitLength;
  }

  @Override
  public int compareTo(P11Identity obj) {
    return id.compareTo(obj.id);
  }

  public boolean supportsMechanism(long mechanism, P11Params parameters) {
    if (publicKey == null) {
      if (PKCS11Constants.CKM_SHA_1_HMAC == mechanism
          || PKCS11Constants.CKM_SHA224_HMAC == mechanism
          || PKCS11Constants.CKM_SHA256_HMAC == mechanism
          || PKCS11Constants.CKM_SHA384_HMAC == mechanism
          || PKCS11Constants.CKM_SHA512_HMAC == mechanism
          || PKCS11Constants.CKM_SHA3_224_HMAC == mechanism
          || PKCS11Constants.CKM_SHA3_256_HMAC == mechanism
          || PKCS11Constants.CKM_SHA3_384_HMAC == mechanism
          || PKCS11Constants.CKM_SHA3_512_HMAC == mechanism) {
        return parameters == null;
      }
    }

    if (publicKey instanceof RSAPublicKey) {
      if (PKCS11Constants.CKM_RSA_9796 == mechanism
          || PKCS11Constants.CKM_RSA_PKCS == mechanism
          || PKCS11Constants.CKM_SHA1_RSA_PKCS == mechanism
          || PKCS11Constants.CKM_SHA224_RSA_PKCS == mechanism
          || PKCS11Constants.CKM_SHA256_RSA_PKCS == mechanism
          || PKCS11Constants.CKM_SHA384_RSA_PKCS == mechanism
          || PKCS11Constants.CKM_SHA512_RSA_PKCS == mechanism) {
        return parameters == null;
      } else if (PKCS11Constants.CKM_RSA_PKCS_PSS == mechanism
          || PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS == mechanism
          || PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS == mechanism
          || PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS == mechanism
          || PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS == mechanism
          || PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS == mechanism) {
        return parameters instanceof P11Params.P11RSAPkcsPssParams;
      } else if (PKCS11Constants.CKM_RSA_X_509 == mechanism) {
        return parameters == null;
      }
    } else if (publicKey instanceof DSAPublicKey) {
      if (parameters != null) {
        return false;
      }
      if (PKCS11Constants.CKM_DSA == mechanism
          || PKCS11Constants.CKM_DSA_SHA1 == mechanism
          || PKCS11Constants.CKM_DSA_SHA224 == mechanism
          || PKCS11Constants.CKM_DSA_SHA256 == mechanism
          || PKCS11Constants.CKM_DSA_SHA384 == mechanism
          || PKCS11Constants.CKM_DSA_SHA512 == mechanism) {
        return true;
      }
    } else if (publicKey instanceof ECPublicKey) {
      if (PKCS11Constants.CKM_ECDSA == mechanism
          || PKCS11Constants.CKM_ECDSA_SHA1 == mechanism
          || PKCS11Constants.CKM_ECDSA_SHA224 == mechanism
          || PKCS11Constants.CKM_ECDSA_SHA256 == mechanism
          || PKCS11Constants.CKM_ECDSA_SHA384 == mechanism
          || PKCS11Constants.CKM_ECDSA_SHA512 == mechanism
          || PKCS11Constants.CKM_VENDOR_SM2 == mechanism) {
        return parameters == null;
      } else if (PKCS11Constants.CKM_VENDOR_SM2_SM3 == mechanism) {
        return parameters instanceof P11Params.P11ByteArrayParams;
      }
    } else if (publicKey instanceof EdDSAKey) {
      if (PKCS11Constants.CKM_EDDSA == mechanism) {
        return true;
      }
    }

    return false;
  } // method supportsMechanism

}
