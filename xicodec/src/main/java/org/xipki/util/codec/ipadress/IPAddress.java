// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.ipadress;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * RFC 3779, 8360
 * <pre>
 * IPAddress ::= BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddress {

  public enum Context {
    PREFIX,
    RANGE_MIN,
    RANGE_MAX,
    C509_RANGE_MIN,
    C509_RANGE_MAX
  }

  private final byte[] value;

  private final int unusedBits;

  public static void main(String[] args) {
    try {
      int afi = IPAddressFamily.AFI_IPv4;
      Context context = Context.PREFIX;
      IPAddress addr = getIPv4Instance("10.0.0.1", context);
      System.out.println(addr.toString(afi, context));

      addr = getIPv4Instance("10.0.1/24", context);
      System.out.println(addr.toString(afi, context));

      context = Context.RANGE_MIN;
      addr = getIPv4Instance("10.2.0.0", context);
      System.out.println(addr.toString(afi, context));

      context = Context.RANGE_MAX;
      addr = getIPv4Instance("10.4.255.255", context);
      System.out.println(addr.toString(afi, context));

      afi = IPAddressFamily.AFI_IPv6;
      context = Context.PREFIX;
      addr = getIPv6Instance("2002:1::/64", context);
      System.out.println(addr.toString(afi, context));

      addr = getIPv6Instance("2002:2::/56", context);
      System.out.println(addr.toString(afi, context));

      context = Context.RANGE_MIN;
      addr = getIPv6Instance("2002:3::", context);
      System.out.println(addr.toString(afi, context));

      context = Context.RANGE_MAX;
      addr = getIPv6Instance("2002:8::fff:ffff:ffff:ffff:ffff", context);
      System.out.println(addr.toString(afi, context));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public IPAddress(byte[] value, int unusedBits) {
    this.unusedBits = unusedBits;
    this.value = Args.notEmptyBytes(value, "value");
  }

  public IPAddress(byte[] value) {
    this(value, 0);
  }

  public byte[] getValue() {
    return value;
  }

  public int getUnusedBits() {
    return unusedBits;
  }

  public String toString(int afi, Context context) {
    byte[] bytes = value.clone();
    if (unusedBits > 0) {
      int b = bytes[bytes.length - 1];
      bytes[bytes.length - 1] = (byte) ((b >> unusedBits) << unusedBits);
    }

    boolean isIPv4 = afi == IPAddressFamily.AFI_IPv4;
    boolean isIPv6 = afi == IPAddressFamily.AFI_IPv6;

    if (context == Context.RANGE_MIN) {
      if (isIPv4 || isIPv6) {
        int len = (afi == IPAddressFamily.AFI_IPv4) ? 4 : 16;
        if (bytes.length < len) {
          bytes = Arrays.copyOf(bytes, len);
        }
      }
    } else if (context == Context.RANGE_MAX) {
      if (isIPv4 || isIPv6) {
        int len = isIPv4 ? 4 : 16;
        // create the mask
        byte[] mask = new byte[len];
        int bytesLen = bytes.length;

        Arrays.fill(mask, (byte) 0xFF);
        for (int i = 0; i < bytesLen; i++) {
          mask[i] = 0;
        }

        if (unusedBits > 0) {
          int k = ~((0xFF >>> unusedBits) << unusedBits);
          mask[bytesLen - 1] = (byte) k;
        }

        for (int i = 0; i < bytesLen; i++) {
          mask[i] |= bytes[i];
        }

        bytes = mask;
      }
    }

    StringBuilder sb = new StringBuilder();
    if (isIPv4) {
      switch (context) {
        case PREFIX:
          for (int i = 0; i < bytes.length; i++) {
            if (i != 0) {
              sb.append(".");
            }
            sb.append(0xFF & bytes[i]);
          }

          int prefixLen = bytes.length * 8 - unusedBits;
          sb.append("/").append(prefixLen);
          break;
        case RANGE_MIN:
        case RANGE_MAX:
          for (int i = 0; i < bytes.length; i++) {
            if (i != 0) {
              sb.append(".");
            }
            sb.append(0xFF & bytes[i]);
          }
      }
    } else if (isIPv6) {
      switch (context) {
        case PREFIX:
          sb.append(toStringIPv6Address(bytes))
              .append("/").append(8 * bytes.length - unusedBits);
          break;
        case RANGE_MIN:
        case RANGE_MAX:
          sb.append(toStringIPv6Address(bytes));
          break;
      }
    } else {
      sb.append(Hex.encode(value)).append(" (unused bits ")
          .append(unusedBits).append(")");
    }
    return sb.toString();
  }

  private static String toStringIPv6Address(byte[] bytes) {
    int numTokens = (bytes.length + 1) / 2;
    int[] tokens = new int[numTokens];
    for (int i = 0; i < numTokens; i++) {
      int off = i * 2;
      tokens[i] = (0xFF & bytes[off]) << 8;
      if (off + 1 < bytes.length) {
        tokens[i] |= (0xFF & bytes[off + 1]);
      }
    }

    int zerosStartIndex = -1;
    int zerosEndIndex = -1;

    for (int i = 0; i < numTokens; i++) {
      int token = tokens[i];
      if (token == 0) {
        if (zerosStartIndex == -1) {
          zerosStartIndex = i;
          zerosEndIndex = i;
        } else {
          zerosEndIndex = i;
        }
      } else {
        if (zerosStartIndex != -1) {
          break;
        }
      }
    }

    StringBuilder sb = new StringBuilder();
    if (zerosStartIndex == -1 || zerosStartIndex == zerosEndIndex) {
      for (int i = 0; i < numTokens; i++) {
        if (i != 0) {
          sb.append(":");
        }

        sb.append(Integer.toHexString(tokens[i]));
      }
    } else {
      for (int i = 0; i < zerosStartIndex; i++) {
        if (i != 0) {
          sb.append(":");
        }

        sb.append(Integer.toHexString(tokens[i]));
      }
      sb.append("::");

      for (int i = zerosEndIndex + 1; i < numTokens; i++) {
        if (i != zerosEndIndex + 1) {
          sb.append(":");
        }
        sb.append(Integer.toHexString(tokens[i]));
      }
    }

    return sb.toString();
  }

  public static IPAddress getIPv4Instance(String str, Context context) {
    return getInstance(true, str, context);
  }

  public static IPAddress getIPv6Instance(String str, Context context) {
    return getInstance(false, str, context);
  }

  public static IPAddress getInstance(
      boolean ipv4, String str, Context context) {
    int numFullBytes = ipv4 ? 4 : 16;

    int prefixLen = -1;
    if (context == Context.PREFIX) {
      prefixLen = 8 * numFullBytes;
      int idx = str.indexOf('/');
      if (idx != -1) {
        prefixLen = Integer.parseInt(str.substring(idx + 1));
        str = str.substring(0, idx);
      }
    }

    byte[] bytes = ipv4 ? toIPv4Bytes(str) : toIPv6Bytes(str);

    switch (context) {
      case PREFIX: {
        int numBytes = (prefixLen + 7) / 8;
        bytes = (bytes.length == numBytes) ? bytes
            : Arrays.copyOf(bytes, numBytes);
        int unusedBits = (8 - (prefixLen % 8)) % 8;

        if (unusedBits != 0) {
          int x = bytes[bytes.length - 1];
          bytes[bytes.length - 1] = (byte) ((x >> unusedBits) << unusedBits);
        }

        return new IPAddress(bytes, unusedBits);
      }
      case RANGE_MIN:
      case RANGE_MAX:
      case C509_RANGE_MIN:
      case C509_RANGE_MAX: {
        BigInteger bn = new BigInteger(1, bytes);
        boolean min = context == Context.RANGE_MIN
            || context == Context.C509_RANGE_MIN;
        int numDefaultBits = 0;
        boolean dfltBitSet = !min;
        for (int i = 0; i < bytes.length * 8; i++) {
          if (dfltBitSet != bn.testBit(i)) {
            break;
          }
          numDefaultBits++;
        }

        if (context == Context.C509_RANGE_MIN
            || context == Context.C509_RANGE_MAX) {
          numDefaultBits = numDefaultBits / 8 * 8;
        }

        bn = bn.shiftRight(numDefaultBits);
        int unusedBits = numDefaultBits % 8;
        if (unusedBits != 0) {
          bn = bn.shiftLeft(unusedBits);
        }

        int numBytes = numFullBytes - numDefaultBits / 8;
        byte[] bnBytes = bn.toByteArray();
        if (bnBytes.length == numBytes) {
          bytes = bnBytes;
        } else if (bnBytes.length < numBytes) {
          System.arraycopy(bnBytes, 0, bytes,
              numBytes - bnBytes.length, bnBytes.length);
        } else {
          System.arraycopy(bnBytes, 1, bytes, 0, numBytes);
        }

        return new IPAddress(bytes, unusedBits);
      }
      default:
        throw new IllegalStateException("shall not reach here");
    }
  }

  private static byte[] toIPv4Bytes(String str) {
    String[] tokens = str.split("\\.");
    if (tokens.length > 4) {
      throw new IllegalArgumentException("invalid IPv4 address " + str);
    }

    byte[] ret = new byte[4];
    for (int i = 0; i < tokens.length; i++) {
      int k = Integer.parseInt(tokens[i]);
      if (k >= 0 && k <= 255) {
        ret[i] = (byte) k;
      } else {
        throw new IllegalArgumentException("invalid IPv4 address " + str);
      }
    }
    return ret;
  }

  private static byte[] toIPv6Bytes(String str) {
    List<Integer> startTokens;
    List<Integer> endTokens;
    int idx = str.indexOf("::");
    if (idx == -1) {
      startTokens = toIPv6Tokens(str);
      endTokens = Collections.emptyList();
    } else {
      startTokens = toIPv6Tokens(str.substring(0, idx));
      endTokens = toIPv6Tokens(str.substring(idx + 2));
    }

    byte[] ret = new byte[16];
    for (int i = 0; i < startTokens.size(); i++) {
      int off = 2 * i;
      int v = startTokens.get(i);
      ret[off] = (byte) (v >> 8);
      ret[off + 1] = (byte) v;
    }

    int off0 = 2 * (8 - endTokens.size());
    for (int i = 0; i < endTokens.size(); i++) {
      int off = off0 + 2 * i;
      int v = endTokens.get(i);
      ret[off] = (byte) (v >> 8);
      ret[off + 1] = (byte) v;
    }

    return ret;
  }

  private static List<Integer> toIPv6Tokens(String str) {
    if (str.isEmpty()) {
      return Collections.emptyList();
    }

    String[] tokens = str.split(":");
    List<Integer> list = new ArrayList<>(tokens.length);
    for (String token : tokens) {
      int i = Integer.parseInt(token, 16);
      if (i >= 0 && i <= 0xFFFF) {
        list.add(i);
      } else {
        throw new IllegalArgumentException("invalid token " + str);
      }
    }
    return list;
  }

}
