// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.type.CkVersion;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Utility class providing util functions to encode and decode basic data types.
 *
 * @author Lijun Liao (xipki)
 */
public class JniUtil {

  public static byte[] encodeLong(Arch arch, long value) {
    byte[] dest = new byte[arch.longSize()];
    JniUtil.writeLong(arch, value, dest, new AtomicInteger());
    return dest;
  }

  public static byte[] encodeLongs(Arch arch, long[] longs) {
    int n = (longs == null) ? 0 : longs.length;
    byte[] dest = new byte[n * arch.longSize()];
    if (n > 0) {
      AtomicInteger off = new AtomicInteger(0);
      for (long value : longs) {
        JniUtil.writeLong(arch, value, dest, off);
      }
    }
    return dest;
  }

  public static long[] readLongs(Arch arch, byte[] encoded) {
    int n = encoded.length / arch.longSize();
    if (encoded.length != n * arch.longSize()) {
      throw new IllegalArgumentException(
          encoded.length + " is not multiple of " + arch.longSize());
    }

    long[] ret = new long[n];
    AtomicInteger off = new AtomicInteger();
    for (int i = 0; i < n; i++) {
      ret[i] = readLong(arch, encoded, off);
    }
    return ret;
  }

  public static void writeLong(Arch arch, long src, byte[] dest,
                               AtomicInteger off) {
    int offset = off.get();
    int n = arch.longSize();
    boolean le = arch.littleEndian();
    for (int i = 0; i < n; i++) {
      dest[offset + (le ? i : n - 1 - i)] = (byte) (src >> (i * 8));
    }
    off.addAndGet(arch.longSize());
  }

  public static long readLong(Arch arch, byte[] encoded) {
    if (encoded.length != arch.longSize()) {
      throw new IllegalArgumentException(
          encoded.length + " is not multiple of " + arch.longSize());
    }

    return readLong(arch, encoded, new AtomicInteger(0));
  }

  public static long readLong(Arch arch, byte[] src, AtomicInteger off) {
    int offset = off.get();
    int n = arch.longSize();
    boolean le = arch.littleEndian();
    long ret = 0;
    for (int i = 0; i < n; i++) {
      ret <<= 8;
      int idx = le ? n - 1 - i : i;
      ret |= 0xFFL & src[offset + idx];
    }
    off.addAndGet(arch.longSize());
    return ret;
  }

  public static int readInt(Arch arch, byte[] src, AtomicInteger off) {
    long v = readLong(arch, src, off);
    if (v > Integer.MAX_VALUE || v < Integer.MIN_VALUE) {
      throw new RuntimeException("value of of range");
    }
    return (int) v;
  }

  public static void writeVersion(
      CkVersion version, byte[] dest, AtomicInteger off) {
    dest[off.getAndIncrement()] = version.major();
    dest[off.getAndIncrement()] = version.minor();
  }

  public static CkVersion readVersion(byte[] src, AtomicInteger off) {
    return new CkVersion(src[off.getAndIncrement()],
                         src[off.getAndIncrement()]);
  }

  public static void writeFixedLenByteArray(
      byte[] src, byte[] dest, AtomicInteger off) {
    System.arraycopy(src, 0, dest, off.get(), src.length);
    off.addAndGet(src.length);
  }

  public static byte[] readFixedLenByteArray(
      byte[] src, int len, AtomicInteger off) {
    return Arrays.copyOfRange(src, off.get(), off.addAndGet(len));
  }

  public static void writeByteArray(Arch arch, byte[] src, byte[] dest,
                                    AtomicInteger off) {
    int len = src == null ? 0 : src.length;
    writeLong(arch, len, dest, off);
    if (len > 0) {
      System.arraycopy(src, 0, dest, off.get(), len);
    }
    off.addAndGet(len);
  }

  public static byte[] readByteArray(Arch arch, byte[] src,
                                     AtomicInteger off) {
    int len = readInt(arch, src, off);
    return Arrays.copyOfRange(src, off.get(), off.addAndGet(len));
  }

  public static int encodedLen(Arch arch, byte[] bytes) {
    return arch.longSize() + (bytes == null ? 0 : bytes.length);
  }

  public static int encodedLen(Arch arch, int numLongs, byte[]... bytesList) {
    int len = numLongs * arch.longSize();
    if (bytesList != null) {
      for (byte[] bytes : bytesList) {
        len += encodedLen(arch, bytes);
      }
    }
    return len;
  }

  public static void encodeTo(
      Arch arch, byte[] dest, AtomicInteger off,
      long[] longs, byte[]... bytesList) {
    encodeTo(arch, dest, off, null, longs, bytesList);
  }

  public static void encodeTo(
      Arch arch, byte[] dest, AtomicInteger off,
      byte[] byteList, long[] longs, byte[]... bytesList) {
    if (byteList != null) {
      JniUtil.writeFixedLenByteArray(byteList, dest, off);
    }

    if (longs != null) {
      for (long value : longs) {
        JniUtil.writeLong(arch, value, dest, off);
      }
    }

    if (bytesList != null) {
      for (byte[] bytes : bytesList) {
        JniUtil.writeByteArray(arch, bytes, dest, off);
      }
    }
  }

  public static byte[] padText(String text, int size) {
    byte[] chars = text.getBytes(StandardCharsets.UTF_8);
    int csize = chars.length;
    if (csize > size) {
      return Arrays.copyOf(chars, size);
    } else if (csize == size) {
      return chars;
    } else {
      byte[] ret = new byte[size];
      Arrays.fill(ret, (byte) ' ');
      System.arraycopy(chars, 0, ret, 0, csize);
      return ret;
    }
  }

}
