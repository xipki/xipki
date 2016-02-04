/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.common.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class StringUtil {

  private StringUtil() {
  }

  public static List<String> split(
      final String str,
      final String delim) {
    if (str == null) {
      return null;
    }

    if (str.isEmpty()) {
      return Collections.emptyList();
    }

    StringTokenizer st = new StringTokenizer(str, delim);
    List<String> ret = new ArrayList<String>(st.countTokens());

    while (st.hasMoreTokens()) {
      ret.add(st.nextToken());
    }

    return ret;
  }

  public static boolean isBlank(
      final String s) {
    return s == null || s.isEmpty();
  }

  public static boolean isNotBlank(
      final String s) {
    return s != null && !s.isEmpty();
  }

  public static Set<String> splitAsSet(
      final String str,
      final String delim) {
    if (str == null) {
      return null;
    }

    if (str.isEmpty()) {
      return Collections.emptySet();
    }

    StringTokenizer st = new StringTokenizer(str, delim);
    Set<String> ret = new HashSet<String>(st.countTokens());

    while (st.hasMoreTokens()) {
      ret.add(st.nextToken());
    }

    return ret;
  }

  public static String collectionAsString(
      final Collection<String> set,
      final String delim) {
    if (set == null) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (String m : set) {
      sb.append(m).append(delim);
    }
    int n = sb.length();
    if (n > 0) {
      sb.delete(n - delim.length(), n);
    }
    return sb.toString();
  }

  public static boolean startsWithIgnoreCase(
      final String s,
      final String prefix) {
    if (s.length() < prefix.length()) {
      return false;
    }

    return prefix.equalsIgnoreCase(s.substring(0, prefix.length()));
  }

  public static boolean isNumber(
      final String s) {
    return isNumber(s, 10);
  }

  public static boolean isNumber(
      final String s,
      final int radix) {
    try {
      Integer.parseInt(s, radix);
      return true;
    } catch (NumberFormatException e) {
      return false;
    }
  }

  public static String formatText(
      final String text,
      final int minLen) {
    int n = text.length();
    if (n >= minLen) {
      return text;
    }

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < minLen - n; i++) {
      sb.append(" ");
    }
    sb.append(text);
    return sb.toString();
  }

  public static String formatAccount(
      final long account,
      final boolean withPrefix) {
    int minLen = withPrefix
        ? 12
        : 0;
    return formatAccount(account, minLen);
  }

  public static String formatAccount(
      final long account,
      final int minLen) {
    String accountS = Long.toString(account);

    final int n = accountS.length();
    if (n > 3) {
      StringBuilder sb = new StringBuilder(n + 3);
      int firstBlockLen = n % 3;
      if (firstBlockLen != 0) {
        sb.append(accountS.substring(0, firstBlockLen));
        sb.append(',');
      }

      for (int i = 0;; i++) {
        int offset = firstBlockLen + i * 3;
        if (offset >= n) {
          break;
        }

        sb.append(accountS.substring(offset, offset + 3));
        if (offset + 3 < n) {
          sb.append(',');
        }
      }
      accountS = sb.toString();
    }

    return formatText(accountS, minLen);
  }

  public static String formatTime(
      final long seconds,
      final boolean withPrefix) {
    int minLen = withPrefix
        ? 12
        : 0;
    return formatTime(seconds, minLen);
  }

  private static String formatTime(
      final long seconds,
      final int minLen) {
    long s = seconds % 60;
    long minutes = seconds / 60;
    long m = minutes % 60;
    long h = minutes / 60;

    StringBuilder sb = new StringBuilder();
    // hours
    if (h > 0) {
      sb.append(h).append(':');
    }

    // minutes
    if (m < 10) {
      sb.append('0');
    }
    sb.append(m).append(':');

    // seconds
    if (s < 10) {
      sb.append('0');
    }
    sb.append(s);

    return formatText(sb.toString(), minLen);
  }

}
