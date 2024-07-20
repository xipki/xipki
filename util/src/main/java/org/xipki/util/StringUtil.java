// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * Utility class for String.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class StringUtil {

  private StringUtil() {
  }

  public static String resolveVariables(String value) {
    // resolve value
    List<String> varTypes = null;
    List<String> varNames = null;
    List<int[]> positions = null;
    for (int i = 0; i < value.length();) {
      if (StringUtil.startsWithIgnoreCase(value, "${env:", i)
          || StringUtil.startsWithIgnoreCase(value, "${sys:", i)) {
        int closeIndex = value.indexOf('}', i + 6); // 6 = "${env:".length() and "${sys:".length()
        if (closeIndex == -1) {
          break;
        } else {
          if (varTypes == null) {
            varTypes = new LinkedList<>();
            varNames = new LinkedList<>();
            positions = new LinkedList<>();
          }

          varTypes.add(StringUtil.startsWithIgnoreCase(value, "${env:", i) ? "env" : "sys");
          varNames.add(value.substring(i + 6, closeIndex));
          positions.add(new int[]{i, closeIndex});

          i = closeIndex + 1;
        }
      } else {
        i++;
      }
    }

    if (varTypes == null) {
      return value;
    }

    StringBuilder valueBuilder = new StringBuilder();
    int firstStartIndex = positions.get(0)[0];
    if (firstStartIndex > 0) {
      valueBuilder.append(value, 0, firstStartIndex);
    }

    int n = positions.size();

    for (int i = 0; i < n; i++) {
      String type = varTypes.get(i);
      String name = varNames.get(i);
      int[] indexes = positions.get(i);

      String thisValue;
      if ("env".equalsIgnoreCase(type)) {
        thisValue = System.getenv(name);
      } else {
        thisValue = System.getProperty(name);
      }

      if (thisValue == null) { // not defined
        thisValue = value.substring(indexes[0], indexes[1] + 1);
      }
      valueBuilder.append(thisValue);

      int nextVarStartIndex = (i == n - 1) ? value.length() : positions.get(i + 1)[0];
      if (nextVarStartIndex > indexes[1] + 1) {
        valueBuilder.append(value, indexes[1] + 1, nextVarStartIndex);
      }
    }

    return valueBuilder.toString();
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
    List<String> tokens = split(str, delim);
    return (tokens == null) ? null : new HashSet<>(tokens);
  }

  public static String[] splitAsArray(String str, String delim) {
    List<String> tokens = split(str, delim);
    return (tokens == null) ? null : tokens.toArray(new String[0]);
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
    return startsWithIgnoreCase(str, prefix, 0);
  }

  public static boolean startsWithIgnoreCase(String str, String prefix, int offset) {
    if (str.length() < offset + prefix.length()) {
      return false;
    }

    return prefix.equalsIgnoreCase(str.substring(offset, offset + prefix.length()));
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
      Integer.parseInt(Args.notNull(str, "str"), radix);
      return true;
    } catch (NumberFormatException ex) {
      return false;
    }
  }

  public static String formatText(String text, int minLen) {
    int len = Args.notNull(text, "text").length();
    if (len >= minLen) {
      return text;
    }

    return " ".repeat(minLen - len) + text;
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

  public static String lowercase(String str) {
    return str == null ? null : str.toLowerCase(Locale.ROOT);
  }

  public static List<String> lowercase(List<String> strs) {
    if (strs == null) {
      return null;
    }

    List<String> ret = new ArrayList<>(strs.size());
    for (String str : strs) {
      ret.add(lowercase(str));
    }
    return ret;
  }

  public static Set<String> lowercase(Set<String> strs) {
    if (strs == null) {
      return null;
    }

    Set<String> ret = new HashSet<>(strs.size());
    for (String str : strs) {
      ret.add(lowercase(str));
    }
    return ret;
  }

  public static String getBundleNameVersion(Class<?> clazz) {
    return getBundleVersion(clazz, true);
  }

  public static String getBundleVersion(Class<?> clazz) {
    return getBundleVersion(clazz, false);
  }

  private static String getBundleVersion(Class<?> clazz, boolean withName) {
    try {
      String className = "/" + clazz.getName().replace(".", "/") + ".class";
      String classPath = clazz.getResource(className).toString();

      String manifestPath = classPath.substring(0, classPath.length() - className.length()) +
          "/META-INF/MANIFEST.MF";
      Manifest manifest = new Manifest(new URL(manifestPath).openStream());
      Attributes attrs = manifest.getMainAttributes();
      String version = attrs.getValue("Bundle-Version");
      if (version == null) {
        return "UNKNOWN";
      }

      String buildNumber = attrs.getValue("Bundle-Build-Id");
      String timestamp = attrs.getValue("Bundle-Build-Timestamp");
      String desc = version + " buildNumber " + buildNumber + " built at " + timestamp;
      if (withName) {
        desc = attrs.getValue("Bundle-SymbolicName") + " " + desc;
      }
      return desc;
    } catch (Exception ex) {
      return "ERROR";
    }
  }

}
