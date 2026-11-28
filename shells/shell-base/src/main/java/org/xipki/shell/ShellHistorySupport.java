// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.impl.history.DefaultHistory;
import org.xipki.util.misc.StringUtil;

import java.time.Instant;
import java.util.Locale;

/**
 * Helpers for masking sensitive values (passwords, PINs) in command lines, before they are
 * persisted in the history or printed while a script is executed.
 *
 * @author Lijun Liao (xipki)
 */
final class ShellHistorySupport {

  /** Key of a password in a configuration string, e.g. "algo=...,password=changeit". */
  private static final String CONF_PASSWORD_KEY = "password=";

  private ShellHistorySupport() {
  }

  /**
   * Masks the sensitive values in the command line: the values of the options whose name ends
   * with "password" or "pwd" and of --pin, and the values of "password=" in configuration
   * strings. References to variables (starting with $) are not masked.
   *
   * @param line the command line.
   * @return the command line with masked sensitive values.
   */
  static String maskSensitiveValues(String line) {
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
      if (eqIndex > 0 && isMaskedOption(token.substring(0, eqIndex))) {
        String valueToken = token.substring(eqIndex + 1);
        if (!isVariableReference(valueToken)) {
          maskRange(chars, i + eqIndex + 1, tokenEnd);
        }
      } else if (isMaskedOption(token)) {
        int valueStart = skipWhitespace(chars, tokenEnd);
        if (valueStart < chars.length) {
          int valueEnd = findTokenEnd(chars, valueStart);
          String valueToken = new String(chars, valueStart, valueEnd - valueStart);
          if (!isVariableReference(valueToken)) {
            maskRange(chars, valueStart, valueEnd);
          }
          tokenEnd = valueEnd;
        }
      } else {
        maskConfPasswords(chars, i, tokenEnd);
      }

      i = tokenEnd;
    }

    return new String(chars);
  }

  private static boolean isMaskedOption(String token) {
    if (!token.startsWith("--")) {
      return false;
    }
    String name = token.toLowerCase(Locale.ROOT);
    // e.g. --password, --signer-password, --inpwd; but not --password-file
    return name.equals("--pin") || name.endsWith("password") || name.endsWith("pwd");
  }

  /**
   * Masks the values of "password=" in a configuration string within the token, e.g.
   * "algo=ECDSA-SHA256,password=changeit,keystore=file:ca.p12".
   */
  private static void maskConfPasswords(char[] chars, int start, int end) {
    String token = new String(chars, start, end - start).toLowerCase(Locale.ROOT);
    int idx = 0;
    while ((idx = token.indexOf(CONF_PASSWORD_KEY, idx)) != -1) {
      // the key starts the token, a pair (after ',') or a quoted string
      char prev = idx == 0 ? ',' : token.charAt(idx - 1);
      idx += CONF_PASSWORD_KEY.length();
      if (prev != ',' && prev != '"' && prev != '\'') {
        continue;
      }

      int valueEnd = idx;
      while (valueEnd < token.length()) {
        char ch = token.charAt(valueEnd);
        if (ch == ',' || ch == '"' || ch == '\'') {
          break;
        }
        valueEnd++;
      }

      if (valueEnd > idx && token.charAt(idx) != '$') {
        for (int k = idx; k < valueEnd; k++) {
          chars[start + k] = '*';
        }
      }
      idx = valueEnd;
    }
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
      super.add(time, maskSensitiveValues(line));
    }
  }

}
