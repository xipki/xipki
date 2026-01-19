// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.jni.JniUtil;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.util.codec.Args;

import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Internal class. Container of fields to be encoded.
 * @author Lijun Liao (xipki)
 */
public class EncodeList {

  private static class ByteW {
    byte v;
  }

  private static class LongW {
    long v;
  }

  private static class ByteArrayW {
    byte[] v;
  }

  private static class FixedLenByteArrayW {
    byte[] v;
  }

  private static class VersionW {
    CkVersion v;
  }

  private static class MechanismW {
    CkMechanism v;
  }

  private final LinkedList<Object> list = new LinkedList<>();

  public EncodeList v(byte[] v) {
    ByteArrayW w = new ByteArrayW();
    w.v = v == null ? new byte[0] : v;
    list.add(w);
    return this;
  }

  public EncodeList v(byte v) {
    ByteW w = new ByteW();
    w.v = v;
    list.add(w);
    return this;
  }

  public EncodeList v(int v) {
    return v(0xFFFFFFFFL & v);
  }

  public EncodeList v(long v) {
    LongW w = new LongW();
    w.v = v;
    list.add(w);
    return this;
  }

  public EncodeList v(boolean v) {
    ByteW w = new ByteW();
    w.v = v ? (byte) 1 : (byte) 0;
    list.add(w);
    return this;
  }

  public EncodeList fixedLenV(byte[] v) {
    FixedLenByteArrayW w = new FixedLenByteArrayW();
    w.v = v == null ? new byte[0] : v;
    list.add(w);
    return this;
  }

  public EncodeList v(CkVersion version) {
    Args.notNull(version, "version");
    VersionW w = new VersionW();
    w.v = version;
    list.add(w);
    return this;
  }

  public EncodeList v(CkMechanism v) {
    MechanismW w = new MechanismW();
    w.v = v;
    list.add(w);
    return this;
  }

  public void writeTo(Arch arch, byte[] dest, AtomicInteger off) {
    for (Object o : list) {
      if (o instanceof ByteW) {
        dest[off.getAndIncrement()] = ((ByteW) o).v;
      } else if (o instanceof LongW) {
        JniUtil.writeLong(arch, ((LongW) o).v, dest, off);
      } else if (o instanceof ByteArrayW) {
        JniUtil.writeByteArray(arch, ((ByteArrayW) o).v, dest, off);
      } else if (o instanceof FixedLenByteArrayW) {
        JniUtil.writeFixedLenByteArray(((FixedLenByteArrayW) o).v, dest, off);
      } else if (o instanceof VersionW) {
        CkVersion v = ((VersionW) o).v;
        dest[off.getAndIncrement()] = v.major();
        dest[off.getAndIncrement()] = v.minor();
      } else {
        CkMechanism mech = ((MechanismW) o).v;
        byte[] encodedMech = mech == null ? new byte[0] : mech.getEncoded(arch);
        JniUtil.writeByteArray(arch, encodedMech, dest, off);
      }
    }
  }

  public int getEncodedLen(Arch arch) {
    int len = 0;
    for (Object o : list) {
      if (o instanceof ByteW) {
        len++;
      } else if (o instanceof LongW) {
        len += arch.longSize();
      } else if (o instanceof ByteArrayW) {
        len += JniUtil.encodedLen(arch, ((ByteArrayW) o).v);
      } else if (o instanceof FixedLenByteArrayW) {
        len += ((FixedLenByteArrayW) o).v.length;
      } else if (o instanceof VersionW) {
        len += 2;
      } else {
        CkMechanism mech = ((MechanismW) o).v;
        len += arch.longSize(); // len(mech)
        if (mech != null) {
          len += mech.getEncodedLen(arch);
        }
      }
    }

    return len;
  }

}
