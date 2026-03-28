// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.impl.history.DefaultHistory;
import org.xipki.util.misc.StringUtil;

import java.time.Instant;
import java.util.Set;

/**
 * History helpers for masking sensitive shell input before it is persisted.
 *
 * @author Lijun Liao (xipki)
 */
final class ShellHistorySupport {

  private static final Set<String> MASKED_OPTIONS = Set.of("--password", "--pin");

  private ShellHistorySupport() {
  }

  static String maskSensitiveHistoryValues(String line) {
    if (StringUtil.isBlank(line)) {
      return line;
    }

    char[] chars = line.toCharArray();
    int i = 0;
    while (i < chars.length) {
      i = skipWhitespace(chars, i);
      if (i >= chars.length) {
        break;
      }

      int tokenEnd = findTokenEnd(chars, i);
      String token = new String(chars, i, tokenEnd - i);

      int eqIndex = token.indexOf('=');
      if (eqIndex > 0) {
        String option = token.substring(0, eqIndex);
        if (MASKED_OPTIONS.contains(option)) {
          String valueToken = token.substring(eqIndex + 1);
          if (!isVariableReference(valueToken)) {
            maskRange(chars, i + eqIndex + 1, tokenEnd);
          }
        }
      } else if (MASKED_OPTIONS.contains(token)) {
        int valueStart = skipWhitespace(chars, tokenEnd);
        if (valueStart < chars.length) {
          int valueEnd = findTokenEnd(chars, valueStart);
          String valueToken = new String(chars, valueStart, valueEnd - valueStart);
          if (!isVariableReference(valueToken)) {
            maskRange(chars, valueStart, valueEnd);
          }
          tokenEnd = valueEnd;
        }
      }

      i = tokenEnd;
    }

    return new String(chars);
  }

  private static int skipWhitespace(char[] chars, int start) {
    int i = start;
    while (i < chars.length && Character.isWhitespace(chars[i])) {
      i++;
    }
    return i;
  }

  private static int findTokenEnd(char[] chars, int start) {
    int i = start;
    boolean inSingle = false;
    boolean inDouble = false;
    while (i < chars.length) {
      char ch = chars[i];
      if (ch == '\'' && !inDouble) {
        inSingle = !inSingle;
      } else if (ch == '"' && !inSingle) {
        inDouble = !inDouble;
      } else if (Character.isWhitespace(ch) && !inSingle && !inDouble) {
        break;
      }
      i++;
    }
    return i;
  }

  private static boolean isVariableReference(String token) {
    String value = token == null ? "" : token.trim();
    if (ShellVariableSupport.isSimpleQuotedLiteral(value)) {
      value = value.substring(1, value.length() - 1);
    }
    return value.startsWith("$");
  }

  private static void maskRange(char[] chars, int start, int end) {
    if (start >= end) {
      return;
    }

    if (end - start >= 2) {
      char first = chars[start];
      char last = chars[end - 1];
      if ((first == '"' || first == '\'') && first == last) {
        for (int i = start + 1; i < end - 1; i++) {
          chars[i] = '*';
        }
        return;
      }
    }

    for (int i = start; i < end; i++) {
      chars[i] = '*';
    }
  }

  static class MaskingHistory extends DefaultHistory {

    @Override
    public void add(Instant time, String line) {
      super.add(time, maskSensitiveHistoryValues(line));
    }
  }

}
