// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.extra.misc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * DER encoding utility functions.
 *
 * @author Lijun Liao (xipki)
 */
public class DerUtil {

  private DerUtil() {
  }

  public static void assertValidDEREncoded(byte[] encoded, String message) {
    if (!isValidDEREncoded(encoded)) {
      throw new IllegalArgumentException(message);
    }
  }

  public static boolean isValidDEREncoded(byte[] encoded) {
    // we do not check the tag and internal structure here, too complicated.
    int len = 0xFF & encoded[1];

    int off = 2;

    if ((len & 0x80) == 0x80) {
      int numLenBytes = len & 0x7F;
      len = 0xFF & encoded[off++];

      if (numLenBytes >= 2) {
        len <<= 8;
        len += encoded[off++];
      }

      if (numLenBytes >= 3) {
        len <<= 8;
        len += encoded[off++];
      }

      if (numLenBytes == 4) {
        if ((len & 0x800000) == 0) {
          return false;
        }
        len <<= 8;
        len += encoded[off++];
      }

      if (numLenBytes >= 5) {
        return false;
      }
    }

    return off + len == encoded.length;
  }

  public static byte[] encodeDerUtf8String(String value) {
    return encodeDerBytes((byte) 0x0C, value.getBytes(StandardCharsets.UTF_8));
  }

  public static byte[] encodeDerUtf8OctetString(byte[] octets) {
    return encodeDerBytes((byte) 0x04, octets);
  }

  public static byte[] encodeDerBytes(byte tag, byte[] data) {
    int len = data.length;
    byte[] lenBytes = encodeLength(len);

    byte[] bytes = new byte[1 + lenBytes.length + len];
    bytes[0] = tag;
    System.arraycopy(lenBytes, 0, bytes, 1, lenBytes.length);
    System.arraycopy(data, 0, bytes, 1 + lenBytes.length, len);
    return bytes;
  }

  public static byte[] encodeLength(int len) {
    if (len <= 0x7F) {
      return new byte[] {(byte) len};
    } else if (len <= 0xFF) {
      return new byte[] {(byte) 0x81, (byte) len};
    } else if (len < 0xFFFF) {
      return new byte[] {(byte) 0x82, (byte) (len >> 8), (byte) len};
    } else if (len < 0xFFFFFF) {
      return new byte[] {(byte) 0x83, (byte) (len >> 16),
          (byte) (len >> 8), (byte) len};
    } else if (len < 0x7FFFFFFF) {
      return new byte[] {(byte) 0x84, (byte) (len >> 24),
          (byte) (len >> 16), (byte) (len >> 8), (byte) len};
    } else {
      throw new IllegalArgumentException("data too long");
    }
  }

  public static int getNumberBytesOfLength(byte[] bytes, int ofs) {
    int b = 0xFF & bytes[ofs];
    return (b & 0x80) == 0 ? 1 : 1 + b & 0x7F;
  }

  public static int getDerLen(byte[] bytes, int ofs, AtomicInteger numLenBytes)
      throws IOException {
    int origOfs = ofs;
    int b = 0xFF & bytes[ofs++];
    int len = ((b & 0x80) == 0) ? b
        : (b == 0x81) ?  0xFF & bytes[ofs++]
        : (b == 0x82) ? (0xFF & bytes[ofs++]) <<  8 | (0xFF & bytes[ofs++])
        : (b == 0x83) ? (0xFF & bytes[ofs++]) << 16
                       | 0xFF & (0xFF & bytes[ofs++]) << 8
                       | (0xFF & bytes[ofs++])
        : (b == 0x84) ? (0xFF & bytes[ofs++]) << 24
                      | (0xFF & bytes[ofs++]) << 16
        | 0xFF & (0xFF & bytes[ofs++]) << 8 | (0xFF & bytes[ofs++])
        : -1;
    if (len == -1) {
      throw new IOException("invalid DER encoded bytes");
    }

    numLenBytes.set(ofs - origOfs);
    return len;
  }

  /**
   * SEQUENCE {
   *   a INTEGER,
   *   b INTEGER
   * }
   * @param encoded the DER encoded bytes.
   * @param ofs the offset
   * @return array with two elements a and b as byte[].
   */
  public static byte[][] readTwoBigIntBytes(
      byte[] encoded, int ofs, int endOffset)
      throws IOException {
    AtomicInteger numLenBytes = new AtomicInteger();

    if (encoded[ofs++] != 0x30) {
      throw new IOException("invalid ASN.1 object");
    }

    int len = DerUtil.getDerLen(encoded, ofs, numLenBytes);
    ofs += numLenBytes.get();

    if (len == 0 || ofs + len != encoded.length) {
      throw new IOException("invalid ASN.1 object");
    }

    // first integer, a
    if (encoded[ofs++] != 0x02) {
      throw new IOException("invalid ASN.1 object");
    }

    int aLen = DerUtil.getDerLen(encoded, ofs, numLenBytes);
    ofs += numLenBytes.get();

    byte[] a = Arrays.copyOfRange(encoded, ofs, ofs + aLen);
    ofs += aLen;

    // second integer, b
    if (encoded[ofs++] != 0x02) {
      throw new IOException("invalid ASN.1 object");
    }

    int bLen = DerUtil.getDerLen(encoded, ofs, numLenBytes);
    ofs += numLenBytes.get();
    if (ofs + bLen != endOffset) {
      throw new IOException("invalid ASN.1 object");
    }

    byte[] b = Arrays.copyOfRange(encoded, ofs, ofs + bLen);

    return new byte[][] {a, b};
  }

  /**
   * Encode the OID (with the leading DER bytes 0x06 || length)
   *
   * @param oid the OID text representation
   * @return the encoded value (with tag and length)
   */
  public static byte[] encodeOid(String oid) {
    byte[] rawOidBytes = encodeRawOid(oid);
    byte[] lenBytes = encodeLength(rawOidBytes.length);
    byte[] oidBytes = new byte[1 + lenBytes.length + rawOidBytes.length];
    oidBytes[0] = 0x06;
    System.arraycopy(lenBytes, 0, oidBytes, 1, lenBytes.length);
    System.arraycopy(rawOidBytes, 0,
        oidBytes, 1 + lenBytes.length, rawOidBytes.length);
    return oidBytes;
  }

  /**
   * Encode the OID (without the leading DER bytes 0x06 || length)
   *
   * @param oid the OID text representation
   * @return the encoded value (without tag and length)
   */
  public static byte[] encodeRawOid(String oid) {
    return encodeRawOid(new ByteArrayOutputStream(10), oid);
  }

  private static byte[] encodeRawOid(ByteArrayOutputStream out, String oid) {
    out.reset();
    String[] nodes = oid.split("\\.");

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

    return out.toByteArray();
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
    if (encoded[0] != 0x06) {
      throw new IllegalArgumentException("invalid OID bytes");
    }

    AtomicInteger numLenBytes = new AtomicInteger(0);
    int len;
    try {
      len = getDerLen(encoded, 1, numLenBytes);
    } catch (IOException e) {
      throw new IllegalArgumentException("invalid OID bytes");
    }

    if (1 + numLenBytes.get() + len != encoded.length) {
      throw new IllegalArgumentException("invalid OID bytes");
    }

    return decodeRawOid(Arrays.copyOfRange(
        encoded, encoded.length - len, encoded.length));
  }

  public static String decodeRawOid(byte[] encoded) {
    final int len = encoded.length;
    if (len < 1) {
      throw new IllegalArgumentException("invalid OID bytes");
    }

    StringBuilder sb = new StringBuilder(len + 3);

    int offset = 0;
    boolean start = true;
    while (offset < len) {
      if (!start) {
        sb.append(".");
      }
      offset = readOidNode(sb, encoded, offset, start);
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
  private static int readOidNode(
      StringBuilder sb, byte[] values, int off, boolean start) {
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

  public static byte[] assertValidRawOid(byte[] oid) {
    decodeRawOid(oid);
    return oid;
  }

  public static boolean isValidRawOid(byte[] oid) {
    try {
      decodeRawOid(oid);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Encode the OID (without the leading DER bytes 0x06 || length
   *
   * @param roid the ROID text representation
   * @return the encoded value (without tag and length)
   */
  public static byte[] encodeRawRoid(String roid) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(10);
    String[] nodes = roid.split("\\.");

    for (String node : nodes) {
      int v = Integer.parseInt(node);
      encodeOidNode(out, v);
    }

    return out.toByteArray();
  }

  public static String decodeRawPen(byte[] encoded) {
    final int len = encoded.length;
    if (len < 1) {
      throw new IllegalArgumentException("invalid OID bytes");
    }

    StringBuilder sb = new StringBuilder(len + 14);
    sb.append("1.3.6.1.4.1");

    int offset = 0;
    while (offset < len) {
      sb.append(".");
      offset = readOidNode(sb, encoded, offset, false);
    }

    if (offset != len) {
      throw new IllegalArgumentException("encoded too long");
    }

    return sb.toString();
  }

  public static byte[] assertValidRawPen(byte[] pen) {
    decodeRawPen(pen);
    return pen;
  }

  public static boolean isValidRawPen(byte[] pen) {
    try {
      decodeRawPen(pen);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

}
