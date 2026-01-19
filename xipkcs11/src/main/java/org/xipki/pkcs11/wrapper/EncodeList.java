// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.jni.JniUtil;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.util.codec.Args;

import java.util.Arrays;
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

  @Override
  public int hashCode() {
    int hashCode = 0;
    for (Object oa : list) {
      int h = 0;
      if (oa instanceof ByteW) {
        h = 0xFF & ((ByteW) oa).v;
      } else if (oa instanceof LongW) {
        h = Long.hashCode(((LongW) oa).v);
      } else if (oa instanceof ByteArrayW) {
        h = Arrays.hashCode(((ByteArrayW) oa).v);
      } else if (oa instanceof FixedLenByteArrayW) {
        h = Arrays.hashCode(((FixedLenByteArrayW) oa).v);
      } else if (oa instanceof VersionW) {
        h = ((VersionW) oa).v.hashCode();
      } else if (oa instanceof MechanismW) {
        h = ((MechanismW) oa).v.hashCode();
      }

      hashCode *= 31;
      hashCode += h;
    }

    return hashCode;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof EncodeList)) {
      return false;
    }

    EncodeList b = (EncodeList) obj;
    int n = list.size();
    if (n != b.list.size()) {
      return false;
    }

    for (int i = 0; i < n; i++) {
      Object oa =  list.get(i);
      Object ob = b.list.get(i);

      if (oa instanceof ByteW) {
        if (ob instanceof ByteW) {
          return ((ByteW) oa).v == ((ByteW) ob).v;
        }
      } else if (oa instanceof LongW) {
        if (ob instanceof LongW) {
          return ((LongW) oa).v == ((LongW) ob).v;
        }
      } else if (oa instanceof ByteArrayW) {
        if (ob instanceof ByteArrayW) {
          return Arrays.equals(((ByteArrayW) oa).v, ((ByteArrayW) ob).v);
        }
      } else if (oa instanceof FixedLenByteArrayW) {
        if (ob instanceof FixedLenByteArrayW) {
          return Arrays.equals(((FixedLenByteArrayW) oa).v,
              ((FixedLenByteArrayW) ob).v);
        }
      } else if (oa instanceof VersionW) {
        if (ob instanceof VersionW) {
          return ((VersionW) oa).v.equals(((VersionW) ob).v);
        }
      } else if (oa instanceof MechanismW) {
        if (ob instanceof MechanismW) {
          return ((MechanismW) oa).v.equals(((MechanismW) ob).v);
        }
      }
    }

    return list.equals(b.list);
  }

}
