// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;

/**
 * {@link P11Key} based on the ipkcs11wrapper or jpkcs11wrapper.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class NativeP11Key extends P11Key {

  NativeP11Key(NativeP11Slot slot, PKCS11KeyId keyId) {
    super(slot, keyId);
  }

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws TokenException {
    return ((NativeP11Slot) slot).digestSecretKey(mechanism, this);
  }

  @Override
  public void destroy() throws TokenException {
    if (keyId.getPublicKeyHandle() == null) {
      slot.destroyObjectsByHandle(keyId.getHandle());
    } else {
      slot.destroyObjectsByHandle(keyId.getHandle(), keyId.getPublicKeyHandle());
    }
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content) throws TokenException {
    return ((NativeP11Slot) slot).sign(mechanism, parameters, content, this);
  }

}
