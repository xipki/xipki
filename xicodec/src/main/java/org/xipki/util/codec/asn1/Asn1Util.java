// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.util.codec.asn1.Asn1Const.TAG_BIT_STRING;
import static org.xipki.util.codec.asn1.Asn1Const.TAG_INTEGER;
import static org.xipki.util.codec.asn1.Asn1Const.TAG_OCTET_STRING;
import static org.xipki.util.codec.asn1.Asn1Const.TAG_OID;
import static org.xipki.util.codec.asn1.Asn1Const.TAG_PRINTABLE_STRING;
import static org.xipki.util.codec.asn1.Asn1Const.TAG_SEQUENCE;
import static org.xipki.util.codec.asn1.Asn1Const.TAG_UTF8_STRING;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Util {

  /**
   * @return the end index (exclusive) of the SEQUENCE.
   */
  static int readSeqPrefix(
      byte[] encoded, AtomicInteger offset, String errMsg)
      throws CodecException {
    return readTagLen(encoded, TAG_SEQUENCE, offset, errMsg);
  }

  /**
   * @return the end index (exclusive) of this element.
   */
  private static int readTagLen(
      byte[] encoded, byte expectedTag, AtomicInteger offset, String errMsg)
      throws CodecException {
    boolean outmost = offset.get() == 0;
    if (encoded[offset.getAndIncrement()] != expectedTag) {
      throw new CodecException(errMsg);
    }

    int len = readDerLen(encoded, offset);
    int endIndex = offset.get() + len;
    boolean valid = outmost ? endIndex == encoded.length
        : endIndex <= encoded.length;

    if (!valid) {
      throw new CodecException(errMsg);
    }

    return offset.get() + len;
  }

  public static byte[] encodeOid(String oid) {
    return encodeOid(new ByteArrayOutputStream(10), oid, true);
  }

  public static byte[] encodeRawOid(String oid) {
    return encodeOid(new ByteArrayOutputStream(10), oid, false);
  }

  private static byte[] encodeOid(ByteArrayOutputStream out, String oid,
                                  boolean addTagLen) {
    out.reset();
    String[] nodes = oid.split("\\.");
    if (addTagLen) {
      out.write(TAG_OID);
      out.write(0); // place holder for length
    }

    // first two nodes
    int node0 = Integer.parseInt(nodes[0]);
    int node1 = Integer.parseInt(nodes[1]);
    boolean valid = ((node0 == 0 || node0 == 1) && (node1 < 40)) || node0 == 2;
    if (!valid) {
      throw new IllegalArgumentException("invalid oid " + oid);
    }

    int nodeValue = node0 * 40 + node1;
    encodeOidNode(out, nodeValue);

    for (int i = 2; i < nodes.length; i++) {
      int v = Integer.parseInt(nodes[i]);
      encodeOidNode(out, v);
    }

    byte[] is = out.toByteArray();
    if (addTagLen) {
      if (is.length - 2 > 127) {
        throw new IllegalStateException("should not reach here, OID too long");
      }
      is[1] = (byte) (is.length - 2);
    }
    return is;
  }

  private static void encodeOidNode(ByteArrayOutputStream out, int nodeValue) {
    if (nodeValue < 128) {
      out.write(nodeValue);
    } else {
      int bitLen = BigInteger.valueOf(nodeValue).bitLength();
      // bitLen=8, numBytes=2, shiftBits = 1
      int numBytes = (bitLen + 6) / 7;
      int shiftBits = bitLen - (numBytes - 1) * 7;
      for (int j = 0; j < numBytes; j++) {
        int k = 0x7F & (nodeValue >> (bitLen - shiftBits - 7 * j));
        if (j != numBytes - 1) {
          k |= 0x80;
        }
        out.write(k);
      }
    }
  }

  public static String decodeOid(byte[] encoded) {
    final int len = encoded.length;
    if (len < 3 || encoded[0] != TAG_OID
        || (0xFF & encoded[1]) != len - 2
        || (encoded[len - 1] & 0x80) != 0) {
      throw new IllegalArgumentException("invalid OID");
    }
    return decodeRawOid(encoded, 2);
  }

  public static String decodeRawOid(byte[] encoded) {
    return decodeRawOid(encoded, 0);
  }

  private static String decodeRawOid(byte[] encoded, int offset) {
    final int len = encoded.length;
    if ((encoded[len - 1] & 0x80) != 0) {
      throw new IllegalArgumentException("invalid OID");
    }

    StringBuilder sb = new StringBuilder(len + 5);

    boolean start = true;
    while (offset < len) {
      if (!start) {
        sb.append(".");
      }
      offset = readNode(sb, encoded, offset, start);
      start = false;
    }

    if (offset != len) {
      throw new IllegalArgumentException("encoded too long");
    }

    return sb.toString();
  }

  /*
   * returns the new offset.
   */
  private static int readNode(StringBuilder sb, byte[] values,
                              int off, boolean start) {
    int nodeValue = 0;
    while (true) {
      int v = 0xff & values[off++];
      boolean hasFurther = (v & 0x80) != 0;
      nodeValue <<= 7;
      nodeValue += (v & 0x7F);
      if (!hasFurther) {
        break;
      }
    }

    if (start) {
      if (nodeValue < 40) {
        sb.append("0.").append(nodeValue);
      } else if (nodeValue < 80) {
        sb.append("1.").append(nodeValue - 40);
      } else {
        sb.append("2.").append(nodeValue - 80);
      }
    } else {
      sb.append(nodeValue);
    }

    return off;
  }

  public static byte[] readTLV(byte[] encoded, AtomicInteger offset)
      throws CodecException {
    int origOfs = offset.getAndIncrement();
    int len = readDerLen(encoded, offset);
    return Arrays.copyOfRange(encoded, origOfs, offset.addAndGet(len));
  }

  public static byte[] readValue(byte[] encoded, AtomicInteger offset)
      throws CodecException {
    int len = readDerLen(encoded, offset);
    return Arrays.copyOfRange(encoded, offset.get(), offset.addAndGet(len));
  }

  public static byte[] readValue(byte[] encoded, AtomicInteger offset,
                                 boolean bitString)
      throws CodecException {
    int len = readDerLen(encoded, offset);
    if (bitString) {
      if (encoded[offset.getAndIncrement()] != 0) {
        throw new CodecException("unused-bits != 0");
      }
    }

    return Arrays.copyOfRange(encoded, offset.get(), offset.addAndGet(len));
  }

  public static byte[] dsaSigPlainToX962(byte[] sig) {
    if (sig.length % 2 != 0) {
      // invalid format, just returns sig.
      return sig;
    }

    int rOrSLen = sig.length / 2;
    byte[] r = Arrays.copyOfRange(sig, 0, rOrSLen);
    byte[] s = Arrays.copyOfRange(sig, rOrSLen, sig.length);
    return toTLV(TAG_SEQUENCE, toAsn1Int(r), toAsn1Int(s));
  }

  public static byte[] dsaSigX962ToPlain(byte[] sig) {
    byte[][] rs;
    try {
      rs = readBigInts(sig, 2);
    } catch (CodecException e) {
      return sig;
    }

    // guess the length of order
    int orderLen = 0;
    for (int i = 0; i < 2; i++) {
      byte[] e = rs[i];
      int eLen = e[0] == 0 ? e.length - 1 : e.length;
      orderLen = Math.max(orderLen, eLen);
    }

    return dsaSigX962ToPlain(sig, rs, orderLen);
  }

  public static byte[] dsaSigX962ToPlain(byte[] sig, int rOrSLen) {
    byte[][] rs;
    try {
      rs = readBigInts(sig, 2);
    } catch (CodecException e) {
      return sig;
    }

    return dsaSigX962ToPlain(sig, rs, rOrSLen);
  }

  private static byte[] dsaSigX962ToPlain(
      byte[] sig, byte[][] rs, int rOrSLen) {
    byte[] ret = new byte[2 * rOrSLen];

    for (int i = 0, off = 0; i < 2; i++, off += rOrSLen) {
      byte[] ele = rs[i];
      if (ele.length > rOrSLen) {
        if (ele.length != rOrSLen + 1 || ele[0] != 0) {
          // invalid sig, just return the original
          return sig;
        }
      }

      System.arraycopy(ele, Math.max(0, ele.length - rOrSLen),
          ret, off + Math.max(0, rOrSLen - ele.length),
          Math.min(rOrSLen, ele.length));
    }

    return ret;
  }

  public static byte[][] readBigInts(byte[] encoded, int num)
      throws CodecException {
    Args.min(num, "num", 1);
    String errMsg = "encodedSeq is not a SEQUENCE";

    AtomicInteger offset = new AtomicInteger();
    int len = readSeqPrefix(encoded, offset, errMsg);
    int endIndex = offset.get() + len;
    byte[][] ret = new byte[num][];

    int i = 0;
    for (; i < num && offset.get() < endIndex; i++) {
      ret[i] = readBigInt(encoded, offset);
    }

    if (i < num) {
      throw new CodecException("expected " + num +
          ", but read only " + i + " INTEGERs");
    }

    offset.set(endIndex);

    return ret;
  }

  public static byte[] readBigInt(byte[] encoded) throws CodecException {
    return readBigInt(encoded, new AtomicInteger());
  }

  public static byte[] readBigInt(byte[] encoded, AtomicInteger offset)
      throws CodecException {
    int off = offset.get();
    if (encoded[off] != TAG_INTEGER) {
      throw new CodecException(
          "encoded[" + off + "] is not an INTEGER");
    }

    offset.incrementAndGet();

    int eLen = readDerLen(encoded, offset);
    return Arrays.copyOfRange(encoded, offset.get(), offset.addAndGet(eLen));
  }

  public static String readStringFromASN1String(byte[] encoded)
      throws CodecException {
    return readStringFromASN1String(encoded, new AtomicInteger());
  }

  public static String readStringFromASN1String(
      byte[] encoded, AtomicInteger offset)
      throws CodecException {
    String errMsg = "encoded is not a valid PrintableString or UTF8String";

    byte tag = encoded[offset.get()];
    if (tag != TAG_UTF8_STRING && tag != TAG_PRINTABLE_STRING) {
      throw new CodecException(errMsg);
    }

    int endIndex = readTagLen(encoded, tag, offset, errMsg);
    if (endIndex != encoded.length) {
      throw new CodecException("encoded is not a valid ASN.1 Printable String");
    }

    // ignore the first byte after the length.
    byte[] bytes = Arrays.copyOfRange(encoded, offset.get(), endIndex);
    boolean utf8 = tag == TAG_UTF8_STRING;
    return new String(bytes,
        utf8 ? StandardCharsets.UTF_8 : StandardCharsets.US_ASCII);
  }

  public static byte[] readOctetsFromASN1OctetString(byte[] encoded)
      throws CodecException {
    return readOctetsFromASN1OctetString(encoded, new AtomicInteger());
  }

  public static byte[] readOctetsFromASN1OctetString(
      byte[] encoded, AtomicInteger offset)
      throws CodecException {
    if (encoded[offset.getAndIncrement()] != TAG_OCTET_STRING) {
      throw new CodecException("encoded is not a valid ASN.1 octet string");
    }

    int len = readDerLen(encoded, offset);
    if (offset.get() + len > encoded.length) {
      throw new CodecException("encoded is not a valid ASN.1 octet string");
    }

    return Arrays.copyOfRange(encoded, offset.get(), offset.addAndGet(len));
  }

  public static byte[] readOctetsFromASN1BitString(byte[] encoded)
      throws CodecException {
    return readOctetsFromASN1BitString(encoded, new AtomicInteger());
  }

  public static byte[] readOctetsFromASN1BitString(
      byte[] encoded, AtomicInteger offset)
      throws CodecException {
    if (encoded[offset.getAndIncrement()] != TAG_BIT_STRING) {
      throw new CodecException("encoded is not a valid ASN.1 bit string");
    }

    int len = readDerLen(encoded, offset);
    if (offset.get() + len > encoded.length) {
      throw new CodecException("encoded is not a valid ASN.1 bit string");
    }

    // ignore the first byte after the length.
    if (encoded[offset.getAndIncrement()] != 0) {
      throw new CodecException("unused-bits != 0");
    }
    return Arrays.copyOfRange(encoded, offset.get(), offset.addAndGet(len - 1));
  }

  public static byte[] toOctetString(byte[] bytes) {
    return toOctetOrBitString(bytes, false);
  }

  public static byte[] toBitString(byte[] bytes) {
    return toOctetOrBitString(bytes, true);
  }

  private static byte[] toOctetOrBitString(byte[] bytes, boolean isBitString) {
    int len = bytes.length;
    if (isBitString) {
      len++;
    }

    byte[] lenBytes = toDerLen(len);;
    byte[] ret = new byte[1 + lenBytes.length + len];

    int off = 0;
    ret[off++] = isBitString ? TAG_BIT_STRING : TAG_OCTET_STRING;

    System.arraycopy(lenBytes, 0, ret, off, lenBytes.length);
    off += lenBytes.length;

    if (isBitString) {
      off++;
    }

    System.arraycopy(bytes, 0, ret, off, bytes.length);
    return ret;
  }

  public static void skipCurrentTLV(byte[] bytes, AtomicInteger offset)
      throws CodecException {
    offset.getAndIncrement(); // tag
    int len = readDerLen(bytes, offset);
    offset.addAndGet(len);
  }

  public static byte[] toAsn1Int(byte[] bytes) {
    // removing leading zeros
    int off = 0;
    for (; off < bytes.length; off++) {
      if (bytes[off] != 0) {
        break;
      }
    }

    if (off == bytes.length) {
      off--;
    }

    int byte0 = bytes[off] & 0xFF;
    if (byte0 > 127) {
      off--;
    }

    if (off == 0) {
      return toTLV(TAG_INTEGER, bytes);
    } else if (off < 0) { // off may be -1
      return toTLV(TAG_INTEGER, new byte[1], bytes);
    } else { // off > 0
      byte[] bs = Arrays.copyOfRange(bytes, off, bytes.length);
      return toTLV(TAG_INTEGER, bs);
    }
  }

  public static byte[] toTLV(byte tag, byte[]... bytesArray) {
    int len = 0;
    for (byte[] bytes : bytesArray) {
      len += bytes.length;
    }

    byte[] lenBytes = toDerLen(len);
    byte[] tlv = new byte[1 + lenBytes.length + len];
    tlv[0] = tag;
    System.arraycopy(lenBytes, 0, tlv, 1, lenBytes.length);

    int off = 1 + lenBytes.length;
    for (byte[] bytes : bytesArray) {
      System.arraycopy(bytes, 0, tlv, off, bytes.length);
      off += bytes.length;
    }

    return tlv;
  }

  public static int readDerLen(byte expectedTag, byte[] bytes,
                               AtomicInteger offset)
      throws CodecException {
    byte tag = bytes[offset.get()];
    if (expectedTag != bytes[offset.get()]) {
      throw new CodecException("tag != " + expectedTag + ": " + tag);
    }

    offset.incrementAndGet();
    return readDerLen(bytes, offset);
  }

  // length
  public static int readDerLen(byte[] bytes, AtomicInteger offset)
      throws CodecException {
    int ofs = offset.get();

    int b = 0xFF & bytes[ofs++];
    int len = ((b & 0x80) == 0) ? b
        : (b == 0x81) ?  0xFF & bytes[ofs++]
        : (b == 0x82) ? (0xFF & bytes[ofs++]) <<  8 | (0xFF & bytes[ofs++])
        : (b == 0x83) ? (0xFF & bytes[ofs++]) << 16 |
                        (0xFF & bytes[ofs++]) <<  8 | (0xFF & bytes[ofs++])
        : (b == 0x84) ? (0xFF & bytes[ofs++]) << 24 |
                        (0xFF & bytes[ofs++]) << 16 |
                        (0xFF & bytes[ofs++]) <<  8 | (0xFF & bytes[ofs++])
        : -1;
    if (len == -1) {
      throw new CodecException("invalid DER encoded bytes");
    }

    offset.set(ofs);
    return len;
  }

  public static byte[] toDerLen(int len) {
    if (len < 128) {
      return new byte[] {(byte) len};
    } else if (len < 0x0100) {
      return new byte[] {(byte) 0x81, (byte) len};
    } else if (len < 0x010000) {
      return new byte[] {(byte) 0x82, (byte) (len >> 8), (byte) len};
    } else if (len < 0x01000000) {
      return new byte[] {(byte) 0x83, (byte) (len >> 16),
          (byte) (len >> 8), (byte) len};
    } else {
      return new byte[] {(byte) 0x84, (byte) (len >> 24), (byte) (len >> 16),
          (byte) (len >> 8), (byte) len};
    }
  }

}
