// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.jni.JniUtil;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Lijun Liao (xipki)
 */
abstract class AbstractInfo extends CkType {

  protected abstract EncodeList getEncodeList();

  @Override
  public int hashCode() {
    return getEncodeList().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof AbstractInfo)) {
      return false;
    }

    String aName = getClass().getName();
    String bName = obj.getClass().getName();
    if (!aName.equals(bName)) {
      return false;
    }

    EncodeList a = getEncodeList();
    EncodeList b = ((AbstractInfo) obj).getEncodeList();
    return a.equals(b);
  }

  public byte[] getEncoded(Arch arch) {
    EncodeList list = getEncodeList();
    int len = list.getEncodedLen(arch);
    byte[] ret = new byte[len];
    list.writeTo(arch, ret, new AtomicInteger());
    return ret;
  }

  protected static long readLong(Arch arch, byte[] encoded, AtomicInteger off) {
    return JniUtil.readLong(arch, encoded, off);
  }

  protected static CkVersion readVersion(byte[] encoded, AtomicInteger off) {
    return JniUtil.readVersion(encoded, off);
  }

  protected static String readFixedLenString(
      int len, byte[] encoded, AtomicInteger off) {
    byte[] bytes = JniUtil.readFixedLenByteArray(encoded, len, off);
    return new String(bytes, StandardCharsets.UTF_8);
  }

}
