// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import org.bouncycastle.pqc.crypto.ExtendedDigest;
import org.bouncycastle.pqc.crypto.Xof;
import org.bouncycastle.pqc.crypto.util.SHA512Digest;

import java.lang.reflect.Constructor;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
class InternalUtil {

  static Xof newSHAKE(int shakeBitLen) {
    String className = "org.bouncycastle.pqc.crypto.util.SHAKEDigest";
    try {
      Class<?> clazz = Class.forName(className, true, BridgeKeyUtil.class.getClassLoader());
      Constructor<?> constructor = clazz.getDeclaredConstructor(int.class);
      constructor.setAccessible(true);
      return (Xof) constructor.newInstance(shakeBitLen);
    } catch (ReflectiveOperationException ex) {
      throw new IllegalStateException("create not create instance from "
          + className + ": " + ex.getMessage(), ex);
    } catch (ClassCastException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    }
  }

  static ExtendedDigest newSHAK512() {
    return new SHA512Digest();
  }

}
