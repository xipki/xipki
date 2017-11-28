/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.common.util;

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

    public static List<String> split(final String str, final String delim) {
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

    public static boolean isBlank(final String str) {
        return str == null || str.isEmpty();
    }

    public static boolean isNotBlank(final String str) {
        return str != null && !str.isEmpty();
    }

    public static Set<String> splitAsSet(final String str, final String delim) {
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

    public static String collectionAsString(final Collection<String> set, final String delim) {
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

    public static boolean startsWithIgnoreCase(final String str, final String prefix) {
        if (str.length() < prefix.length()) {
            return false;
        }

        return prefix.equalsIgnoreCase(str.substring(0, prefix.length()));
    }

    public static boolean isNumber(final String str) {
        return isNumber(str, 10);
    }

    public static boolean isNumber(final String str, final int radix) {
        ParamUtil.requireNonNull("str", str);
        try {
            Integer.parseInt(str, radix);
            return true;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    public static String formatText(final String text, final int minLen) {
        ParamUtil.requireNonNull("text", text);
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

    public static String formatAccount(final long account, final boolean withPrefix) {
        int minLen = withPrefix ? 12 : 0;
        return formatAccount(account, minLen);
    }

    public static String formatAccount(final long account, final int minLen) {
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

    public static String formatTime(final long seconds, final boolean withPrefix) {
        int minLen = withPrefix ? 12 : 0;
        return formatTime(seconds, minLen);
    }

    private static String formatTime(final long seconds, final int minLen) {
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
        for (int i = 0; i < parts.length; i++) {
            sum += parts[i].length;
        }

        char[] ret = new char[sum];
        int destPos = 0;
        for (int i = 0; i < parts.length; i++) {
            char[] part = parts[i];
            System.arraycopy(part, 0, ret, destPos, part.length);
            destPos += part.length;
        }
        return ret;
    }
}
