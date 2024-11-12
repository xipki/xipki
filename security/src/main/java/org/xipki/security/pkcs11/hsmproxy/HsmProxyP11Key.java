// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.hsmproxy;

import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.params.ExtraParams;
import org.xipki.security.pkcs11.P11Key;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_RSA;

/**
 * {@link P11Key} based on the HSM proxy.
 *
 * @author Lijun Liao (xipki)
 */

class HsmProxyP11Key extends P11Key {

  public HsmProxyP11Key(HsmProxyP11Slot slot, PKCS11KeyId keyId) {
    super(slot, keyId);
  }

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws TokenException {
    return slot.digestSecretKey(mechanism, keyId.getHandle());
  }

  @Override
  protected PublicKey getPublicKey0() throws TokenException {
    long keyType = keyId.getKeyType();
    if (keyType == CKK_RSA) {
      try {
        return KeyUtil.generateRSAPublicKey(
            new RSAPublicKeySpec(rsaModulus, rsaPublicExponent));
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    }

    Long publicKeyHandle = keyId.getPublicKeyHandle();
    return (publicKeyHandle == null) ? null : slot.getPublicKey(publicKeyHandle);
  }

  @Override
  public void destroy() throws TokenException {
    long[] failedHandles;
    if (keyId.getPublicKeyHandle() == null) {
      failedHandles = slot.destroyObjectsByHandle(keyId.getHandle());
    } else {
      failedHandles = slot.destroyObjectsByHandle(keyId.getHandle(), keyId.getPublicKeyHandle());
    }
    if (failedHandles != null && failedHandles.length > 0) {
      throw new TokenException("error destroying key " + keyId);
    }
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content) throws TokenException {
    Args.notNull(content, "content");
    ExtraParams extraParams = null;
    if (ecOrderBitSize != null) {
      extraParams = new ExtraParams();
      extraParams.ecOrderBitSize(ecOrderBitSize);
    }

    return slot.sign(mechanism, parameters, extraParams, keyId.getHandle(), content);
  }

}
