package org.xipki.util;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Utility methods for converting byte arrays into ints and longs, and back again.
 */
public abstract class PackUtil {
  public static short bigEndianToShort(byte[] bs, int off) {
    int n = (bs[off] & 0xff) << 8;
    n |= (bs[++off] & 0xff);
    return (short) n;
  }

  public static int bigEndianToInt(byte[] bs, int off) {
    int n = bs[off] << 24;
    n |= (bs[++off] & 0xff) << 16;
    n |= (bs[++off] & 0xff) << 8;
    n |= (bs[++off] & 0xff);
    return n;
  }

  public static void bigEndianToInt(byte[] bs, int off, int[] ns) {
    for (int i = 0; i < ns.length; ++i) {
      ns[i] = bigEndianToInt(bs, off);
      off += 4;
    }
  }

  public static void bigEndianToInt(byte[] bs, int off, int[] ns, int nsOff, int nsLen) {
    for (int i = 0; i < nsLen; ++i) {
      ns[nsOff + i] = bigEndianToInt(bs, off);
      off += 4;
    }
  }

  public static byte[] intToBigEndian(int n) {
    byte[] bs = new byte[4];
    intToBigEndian(n, bs, 0);
    return bs;
  }

  public static void intToBigEndian(int n, byte[] bs, int off) {
    bs[off] = (byte)(n >>> 24);
    bs[++off] = (byte)(n >>> 16);
    bs[++off] = (byte)(n >>> 8);
    bs[++off] = (byte)(n);
  }

  public static byte[] intToBigEndian(int[] ns) {
    byte[] bs = new byte[4 * ns.length];
    intToBigEndian(ns, bs, 0);
    return bs;
  }

  public static void intToBigEndian(int[] ns, byte[] bs, int off) {
    for (int n : ns) {
      intToBigEndian(n, bs, off);
      off += 4;
    }
  }

  public static void intToBigEndian(int[] ns, int nsOff, int nsLen, byte[] bs, int bsOff) {
    for (int i = 0; i < nsLen; ++i) {
      intToBigEndian(ns[nsOff + i], bs, bsOff);
      bsOff += 4;
    }
  }

  public static long bigEndianToLong(byte[] bs, int off) {
    int hi = bigEndianToInt(bs, off);
    int lo = bigEndianToInt(bs, off + 4);
    return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
  }

  public static void bigEndianToLong(byte[] bs, int off, long[] ns) {
    for (int i = 0; i < ns.length; ++i) {
      ns[i] = bigEndianToLong(bs, off);
      off += 8;
    }
  }

  public static void bigEndianToLong(byte[] bs, int bsOff, long[] ns, int nsOff, int nsLen) {
    for (int i = 0; i < nsLen; ++i) {
      ns[nsOff + i] = bigEndianToLong(bs, bsOff);
      bsOff += 8;
    }
  }

  public static byte[] longToBigEndian(long n) {
    byte[] bs = new byte[8];
    longToBigEndian(n, bs, 0);
    return bs;
  }

  public static void longToBigEndian(long n, byte[] bs, int off) {
    intToBigEndian((int)(n >>> 32), bs, off);
    intToBigEndian((int)(n & 0xffffffffL), bs, off + 4);
  }

  public static byte[] longToBigEndian(long[] ns) {
    byte[] bs = new byte[8 * ns.length];
    longToBigEndian(ns, bs, 0);
    return bs;
  }

  public static void longToBigEndian(long[] ns, byte[] bs, int off) {
    for (long n : ns) {
      longToBigEndian(n, bs, off);
      off += 8;
    }
  }

  public static void longToBigEndian(long[] ns, int nsOff, int nsLen, byte[] bs, int bsOff) {
    for (int i = 0; i < nsLen; ++i) {
      longToBigEndian(ns[nsOff + i], bs, bsOff);
      bsOff += 8;
    }
  }

  public static byte[] shortToBigEndian(short n) {
    byte[] r = new byte[2];
    shortToBigEndian(n, r, 0);
    return r;
  }

  public static void shortToBigEndian(short n, byte[] bs, int off) {
    bs[off] = (byte)(n >>> 8);
    bs[++off] = (byte)(n);
  }

  public static byte[] asUnsignedByteArray(BigInteger bn) {
    byte[] bytes = bn.toByteArray();
    if (bytes.length > 1 && bytes[0] == 0) {
      return Arrays.copyOfRange(bytes, 1, bytes.length);
    } else {
      return bytes;
    }
  }

  public static int[] intObj2Int(Integer[] ints) {
    int[] ret = new int[ints.length];
    for (int i = 0; i < ints.length; i++) {
      ret[i] = ints[i];
    }
    return ret;
  }

}
