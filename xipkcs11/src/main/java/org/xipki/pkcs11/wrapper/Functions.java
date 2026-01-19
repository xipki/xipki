// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.asn1.Asn1Const;
import org.xipki.util.codec.asn1.Asn1Util;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Lijun Liao (xipki)
 */
public class Functions {

  private static class ECInfo {
    int fieldSize;
    int orderSize;
    int orderBitLength;
    String oid;
    String[] names;
    byte[] order;
    byte[] baseX;
  }

  private static final Map<String, ECInfo> ecParamsInfoMap;

  static {
    ecParamsInfoMap = new HashMap<>(120);

    String propFile = "org/xipki/pkcs11/wrapper/ec.json";
    try (InputStream is = Functions.class.getClassLoader()
                            .getResourceAsStream(propFile)) {
      JsonList json = JsonParser.parseList(is, true);
      for (JsonMap v : json.toMapList()) {
        ECInfo ecInfo = new ECInfo();

        String oid = v.getNnString("oid");
        ecInfo.oid = oid;
        if (ecParamsInfoMap.containsKey(oid)) {
          throw new IllegalStateException("duplicated definition of " + oid);
        }

        byte[] ecParams = Asn1Util.encodeOid(ecInfo.oid);

        ecInfo.names = v.getStringArray("names");
        ecInfo.fieldSize = v.getInt("fieldSize");

        String str = v.getString("order");
        if (str != null) {
          BigInteger bn = new BigInteger(str, 16);
          ecInfo.order = bn.toByteArray();
          ecInfo.orderBitLength = bn.bitLength();
        } else {
          ecInfo.orderBitLength = v.getNnInt("orderSize");
        }
        ecInfo.orderSize = (ecInfo.orderBitLength + 7) / 8;

        str = v.getString("baseX");
        if (str != null) {
          ecInfo.baseX = new BigInteger(str, 16).toByteArray();
        }

        String hexEcParams = Hex.encode(ecParams, 0, ecParams.length);

        ecParamsInfoMap.put(hexEcParams, ecInfo);
      }
    } catch (Throwable t) {
      throw new IllegalStateException("error reading properties file " +
          propFile + ": " + t.getMessage());
    }
  }

  public static byte[] asUnsignedByteArray(java.math.BigInteger bn) {
    byte[] bytes = bn.toByteArray();
    return bytes[0] != 0 ? bytes : Arrays.copyOfRange(bytes, 1, bytes.length);
  }

  /**
   * Converts a long value to a lower-case hexadecimal String of length 16.
   * Includes leading zeros if necessary.
   *
   * @param value The long value to be converted.
   * @return The hexadecimal string representation of the long value.
   */
  public static String toFullHex(long value) {
    return toFullHex(value, false);
  }

  /**
   * Converts a long value to an upper-case hexadecimal String of length 16.
   * Includes leading zeros if necessary.
   *
   * @param value The long value to be converted.
   * @return The hexadecimal string representation of the long value.
   */
  public static String toFullHexUpper(long value) {
    return toFullHex(value, true);
  }

  private static final char[] DIGITS = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  private static final char[] UPPER_DIGITS = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  private static String toFullHex(long value, boolean upperCase) {
    long currentValue = value;
    StringBuilder stringBuffer = new StringBuilder(16);
    final int size = value > 0xFFFFFFFFL ? 16 : 8;
    for (int j = 0; j < size; j++) {
      int currentDigit = (int) currentValue & 0xf;
      stringBuffer.append((upperCase ? UPPER_DIGITS : DIGITS)[currentDigit]);
      currentValue >>>= 4;
    }

    return stringBuffer.reverse().toString();
  }

  /**
   * Converts a byte array to a hexadecimal String. Each byte is presented by
   * its two digit hex-code; 0x0A -&gt; "0a", 0x00 -&gt; "00". No leading "0x"
   * is included in the result.
   *
   * @param value the byte array to be converted
   * @return the hexadecimal string representation of the byte array
   */
  public static String toHex(byte[] value) {
    return Hex.encode(value, 0, value.length);
  }

  public static String toHex(byte[] value, int ofs, int len) {
    return Hex.encode(value, ofs, len);
  }

  public static byte[] decodeHex(String encoded) {
    return Hex.decode(encoded);
  }

  public static Long parseLong(String text) {
    if (text.startsWith("0x") || text.startsWith("0X")) {
      return Long.parseLong(text.substring(2), 16);
    } else {
      boolean isNumber = true;
      boolean withSign = text.startsWith("-");
      for (int i = (withSign ? 1 : 0); i < text.length(); i++) {
        char c = text.charAt(i);
        if (c > '9' || c < '0') {
          isNumber = false;
          break;
        }
      }

      if (isNumber) {
        return Long.parseLong(text);
      } else {
        return null;
      }
    }
  }

  public static String toStringFlags(Category category, String prefix,
                                     long flags, long... flagMasks) {
    // initialize the indent for non-first lines.
    char[] indentChars = new char[prefix.length() + 1];
    Arrays.fill(indentChars, ' ');
    String indent = new String(indentChars);

    ArrayList<Long> sortedMasks = new ArrayList<>(flagMasks.length);
    for (long flagMask : flagMasks) {
      sortedMasks.add(flagMask);
    }
    java.util.Collections.sort(sortedMasks);

    boolean first = true;
    List<String> lines = new LinkedList<>();

    String line = prefix + "0x" + toFullHex(flags) + " (";
    for (long flagMask : sortedMasks) {
      if ((flags & flagMask) == 0L) {
        continue;
      }

      String thisEntry = first ? "" : " | ";

      if (first) {
        first = false;
      }

      // 4 = "CKF_".length
      thisEntry += PKCS11T.codeToName(category, flagMask).substring(4);
      if (line.length() + thisEntry.length() > 100) {
        lines.add(line);
        line = indent;
      }
      line += thisEntry;
    }

    if (line.length() > indentChars.length) {
      lines.add(line);
    }

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < lines.size(); i++) {
      if (i != 0) {
        sb.append("\n");
      }

      sb.append(lines.get(i));
    }
    return sb.append(")").toString();
  }

  public static byte[] getEcParams(BigInteger order, BigInteger baseX) {
    byte[] orderBytes = order.toByteArray();
    byte[] baseXBytes = baseX.toByteArray();
    for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
      ECInfo ei = m.getValue();
      if (Arrays.equals(ei.order, orderBytes)
          && Arrays.equals(ei.baseX, baseXBytes)) {
        return Hex.decode(m.getKey());
      }
    }
    return null;
  }

  public static Integer getCurveOrderBitLength(byte[] ecParams) {
    ECInfo ecInfo = ecParamsInfoMap.get(
        Hex.encode(ecParams, 0, ecParams.length));
    return (ecInfo == null) ? null : ecInfo.orderBitLength;
  }

  public static String getCurveName(byte[] ecParams) {
    ECInfo ecInfo = getECInfo(ecParams);
    return ecInfo == null ? null : ecInfo.names[0];
  }

  public static String getCurveOID(byte[] ecParams) {
    ECInfo ecInfo = getECInfo(ecParams);
    return ecInfo == null ? null : ecInfo.oid;
  }

  public static String[] getCurveNames(byte[] ecParams) {
    ECInfo ecInfo = getECInfo(ecParams);
    return ecInfo == null ? null : ecInfo.names.clone();
  }

  private static ECInfo getECInfo(byte[] ecParams) {
    // by OID
    ECInfo ecInfo = ecParamsInfoMap.get(
        Hex.encode(ecParams, 0, ecParams.length));
    if (ecInfo != null) {
      return ecInfo;
    }

    String curveName;
    try {
      curveName = Asn1Util.readStringFromASN1String(ecParams);
    } catch (CodecException e) {
      return null;
    }

    for (ECInfo v : ecParamsInfoMap.values()) {
      for (String n : v.names) {
        if (n.equalsIgnoreCase(curveName)) {
          return v;
        }
      }
    }

    return null;
  }

  public static byte[] fixECDSASignature(byte[] sig, byte[] ecParams) {
    ECInfo ecInfo = ecParamsInfoMap.get(
        Hex.encode(ecParams, 0, ecParams.length));
    if (ecInfo == null) {
      return sig;
    }

    return fixECDSASignature(sig, ecInfo.orderSize);
  }

  public static byte[] fixECDSASignature(byte[] sig, int rOrSLen) {
    if (sig.length == 2 * rOrSLen || sig[0] != Asn1Const.TAG_SEQUENCE) {
      return sig;
    }
    return Asn1Util.dsaSigX962ToPlain(sig, rOrSLen);
  }

  public static byte[] fixECParams(byte[] ecParams) {
    try {
      // some HSMs, e.g. SoftHSM may return the ASN.1 Printable string, e.g.
      // edwards25519 for ED25519,and curve25519 for X25519.
      int tag = 0xFF & ecParams[0];
      if (tag == 12 || tag == 19) { // 12: UTF8 String, 19: Printable String
        AtomicInteger offset = new AtomicInteger(1);
        int len = Asn1Util.readDerLen(ecParams, offset);

        if (offset.get() + len == ecParams.length) {
          String curveName = new String(ecParams, offset.get(), len,
              StandardCharsets.UTF_8).trim().toUpperCase(Locale.ROOT);
          for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
            for (String name : m.getValue().names) {
              if (name.equals(curveName)) {
                return decodeHex(m.getKey());
              }
            }
          }
        }

        return ecParams;
      }

      return ecParams;
    } catch (Exception e) {
      return ecParams;
    }
  }

  public static String toString(String prefix, byte[] bytes) {
    final int numPerLine = 40;
    final int len = bytes.length;
    int indentLen = prefix.length();
    if (indentLen > 0 && prefix.charAt(0) == '\n') {
      indentLen--;
    }

    char[] indentChars = new char[indentLen];
    Arrays.fill(indentChars, ' ');
    String indent = "\n" + new String(indentChars);

    StringBuilder sb = new StringBuilder(
        5 * (len + numPerLine - 1) / numPerLine + 4 * bytes.length);
    for (int ofs = 0; ofs < len; ofs += numPerLine) {
      int num = Math.min(numPerLine, len - ofs);
      sb.append(ofs == 0 ? prefix : indent).append(toHex(bytes, ofs, num));
    }
    return sb.toString();
  }

}
