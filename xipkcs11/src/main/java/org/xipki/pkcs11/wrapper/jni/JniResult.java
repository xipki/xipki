// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncapKeyResult;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkInfo;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSessionInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class specifies the result returned by the JNI part.
 *
 * @author Lijun Liao (xipki)
 */
public class JniResult {

  private final Arch arch;

  private final JniResp resp;

  private final byte[] payload;

  public JniResult(Arch arch, JniResp resp, byte[] payload) {
    this.arch = arch;
    this.resp = resp;
    this.payload = payload;
  }

  public JniResp resp() {
    return resp;
  }

  public boolean hasPayload() {
    return payload != null && payload.length > 0;
  }

  public byte[] payload() {
    return payload;
  }

  public long longPayload() {
    return JniUtil.readLong(arch, payload, new AtomicInteger());
  }

  public long[] longArrayPayload() {
    int len = payload.length;
    int n = len / arch.longSize();
    if (n * arch.longSize() != len) {
      throw new IllegalArgumentException(
          len + " is not multiple of " + arch.longSize());
    }

    AtomicInteger off = new AtomicInteger(0);
    long[] longs = new long[n];
    for (int i = 0; i < n; i++) {
      longs[i] = JniUtil.readLong(arch, payload, off);
    }

    return longs;
  }

  public CkInfo infoPayload() {
    return CkInfo.decode(arch, payload);
  }

  public CkSlotInfo slotInfoPayload() {
    return CkSlotInfo.decode(arch, payload);
  }

  public CkTokenInfo tokenInfoPayload() {
    return CkTokenInfo.decode(arch, payload);
  }

  public CkSessionInfo sessionInfoPayload() {
    return CkSessionInfo.decode(arch, payload);
  }

  public CkMechanismInfo mechanismInfoPayload() {
    return CkMechanismInfo.decode(arch, payload);
  }

  public Template templatePayload() {
    return Template.decode(arch, payload);
  }

  public EncapKeyResult encapKeyPayload() {
    return new EncapKeyResult(((JniResp.JniLongResp) resp).value(), payload);
  }

}
