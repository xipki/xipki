// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.xipki.util.Args.notNull;

/**
 * Utility class for String.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class StringUtil {

  private StringUtil() {
  }

  public static List<String> split(String str, String delim) {
    if (str == null) {
      return null;
    }

    if (str.isEmpty()) {
      return Collections.emptyList();
    }

    StringTokenizer st = new StringTokenizer(str, delim);
    List<String> ret = new ArrayList<>(st.countTokens());

    while (st.hasMoreTokens()) {
      ret.add(st.nextToken());
    }

    return ret;
  }

  public static boolean isBlank(String str) {
    return str == null || str.isEmpty();
  }

  public static boolean isNotBlank(String str) {
    return str != null && !str.isEmpty();
  }

  public static Set<String> splitAsSet(String str, String delim) {
    if (str == null) {
      return null;
    }

    if (str.isEmpty()) {
      return Collections.emptySet();
    }

    StringTokenizer st = new StringTokenizer(str, delim);
    Set<String> ret = new HashSet<>(st.countTokens());

    while (st.hasMoreTokens()) {
      ret.add(st.nextToken());
    }

    return ret;
  }

  public static String collectionAsString(Collection<String> set, String delim) {
    if (set == null) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (String m : set) {
      sb.append(m).append(delim);
    }
    int len = sb.length();
    if (len > 0) {
      sb.delete(len - delim.length(), len);
    }
    return sb.toString();
  }

  public static boolean startsWithIgnoreCase(String str, String prefix) {
    if (str.length() < prefix.length()) {
      return false;
    }

    return prefix.equalsIgnoreCase(str.substring(0, prefix.length()));
  }

  public static boolean orEqualsIgnoreCase(String str, String... tokens) {
    if (str == null) {
      return false;
    }

    for (String token : tokens) {
      if (str.equalsIgnoreCase(token)) {
        return true;
      }
    }
    return false;
  }

  public static boolean isNumber(String str) {
    return isNumber(str, 10);
  }

  public static boolean isNumber(String str, int radix) {
    try {
      Integer.parseInt(notNull(str, "str"), radix);
      return true;
    } catch (NumberFormatException ex) {
      return false;
    }
  }

  public static String formatText(String text, int minLen) {
    notNull(text, "text");
    int len = text.length();
    if (len >= minLen) {
      return text;
    }

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < minLen - len; i++) {
      sb.append(" ");
    }
    sb.append(text);
    return sb.toString();
  }

  public static String formatAccount(long account, boolean withPrefix) {
    return formatAccount(account, withPrefix ? 12 : 0);
  }

  public static String formatAccount(long account, int minLen) {
    String accountS = Long.toString(account);

    final int n = accountS.length();
    if (n > 3) {
      StringBuilder sb = new StringBuilder(n + 3);
      int firstBlockLen = n % 3;
      if (firstBlockLen != 0) {
        sb.append(accountS, 0, firstBlockLen).append(',');
      }

      for (int i = 0;; i++) {
        int offset = firstBlockLen + i * 3;
        if (offset >= n) {
          break;
        }

        sb.append(accountS, offset, offset + 3);
        if (offset + 3 < n) {
          sb.append(',');
        }
      }
      accountS = sb.toString();
    }

    return formatText(accountS, minLen);
  }

  public static String formatTime(long seconds, boolean withPrefix) {
    return formatTime(seconds, withPrefix ? 12 : 0);
  }

  public static String formatTime(long seconds, int minLen) {
    long minutes = seconds / 60;

    StringBuilder sb = new StringBuilder();
    long hour = minutes / 60;
    // hours
    if (hour > 0) {
      sb.append(hour).append(':');
    }

    long modMinute = minutes % 60;
    // minutes
    if (modMinute < 10) {
      sb.append('0');
    }
    sb.append(modMinute).append(':');

    long modSec = seconds % 60;
    // seconds
    if (modSec < 10) {
      sb.append('0');
    }
    sb.append(modSec);

    return formatText(sb.toString(), minLen);
  }

  public static char[] merge(char[][] parts) {
    int sum = 0;
    for (char[] chars : parts) {
      sum += chars.length;
    }

    char[] ret = new char[sum];
    int destPos = 0;
    for (char[] part : parts) {
      System.arraycopy(part, 0, ret, destPos, part.length);
      destPos += part.length;
    }
    return ret;
  }

  public static String concat(String s1, String... strs) {
    int len = (s1 == null) ? 4 : s1.length();
    for (String str : strs) {
      len += (str == null) ? 4 : str.length();
    }
    StringBuilder sb = new StringBuilder(len).append(s1);
    for (String str : strs) {
      sb.append(str);
    }
    return sb.toString();
  }

  public static String concatObjects(Object o1, Object... objs) {
    StringBuilder sb = new StringBuilder().append(o1);
    for (Object obj : objs) {
      sb.append(obj);
    }
    return sb.toString();
  }

  public static String concatObjectsCap(int cap, Object o1, Object... objs) {
    StringBuilder sb = new StringBuilder(cap).append(o1);
    for (Object obj : objs) {
      sb.append(obj);
    }
    return sb.toString();
  }

  public static byte[] toUtf8Bytes(String str) {
    return (str == null) ? null : str.getBytes(StandardCharsets.UTF_8);
  }

  public static String toUtf8String(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }

  public static BigInteger toBigInt(String str) {
    return toBigInt(str, false);
  }

  public static BigInteger toBigInt(String str, boolean defaultHex) {
    String tmpStr = str.trim();

    if (tmpStr.startsWith("0x") || tmpStr.startsWith("0X")) {
      if (tmpStr.length() > 2) {
        return new BigInteger(tmpStr.substring(2), 16);
      } else {
        throw new NumberFormatException("invalid integer '" + tmpStr + "'");
      }
    }
    return new BigInteger(tmpStr, defaultHex ? 16 : 10);
  }

  public static String getVersion(Class clazz) {
    try {
      return toUtf8String(IoUtil.read(clazz.getResourceAsStream("/version"))).trim();
    } catch (Exception ex) {
      return "UNKNOWN";
    }
  }

}
