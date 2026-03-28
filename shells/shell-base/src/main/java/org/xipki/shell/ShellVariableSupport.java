// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility methods for shell variable interpolation.
 *
 * @author Lijun Liao (xipki)
 */
final class ShellVariableSupport {

  interface Resolver {
    String lookup(String bracedName, String simpleName);
  }

  private static final Pattern VARIABLE_PATTERN = Pattern.compile(
      "\\$(?:\\{([^}]+)\\}|([A-Za-z_][A-Za-z0-9_]*|[0-9]+))");

  private ShellVariableSupport() {
  }

  static String interpolateVariables(String text, Resolver resolver) {
    String value = text == null ? "" : text.trim();
    if (isSimpleQuotedLiteral(value)) {
      value = value.substring(1, value.length() - 1);
    }

    Matcher matcher = VARIABLE_PATTERN.matcher(value);
    StringBuilder sb = new StringBuilder(value.length());
    int lastEnd = 0;
    while (matcher.find()) {
      String prefix = value.substring(lastEnd, matcher.start());
      int trailingBackslashes = countTrailingBackslashes(prefix);
      sb.append(prefix, 0, prefix.length() - trailingBackslashes);
      appendBackslashes(sb, trailingBackslashes / 2);

      String replacement;
      if ((trailingBackslashes & 1) == 1) {
        replacement = matcher.group(0);
      } else {
        replacement = resolver.lookup(matcher.group(1), matcher.group(2));
        if (replacement == null) {
          replacement = matcher.group(0);
        }
      }

      sb.append(replacement);
      lastEnd = matcher.end();
    }

    if (lastEnd < value.length()) {
      sb.append(value.substring(lastEnd));
    }
    return sb.toString();
  }

  static boolean isSimpleQuotedLiteral(String value) {
    if (value == null || value.length() < 2) {
      return false;
    }

    char first = value.charAt(0);
    char last = value.charAt(value.length() - 1);
    if ((first != '"' && first != '\'') || first != last) {
      return false;
    }

    return value.substring(1, value.length() - 1).indexOf(first) == -1;
  }

  private static int countTrailingBackslashes(String text) {
    int count = 0;
    for (int i = text.length() - 1; i >= 0 && text.charAt(i) == '\\'; i--) {
      count++;
    }
    return count;
  }

  private static void appendBackslashes(StringBuilder sb, int count) {
    for (int i = 0; i < count; i++) {
      sb.append('\\');
    }
  }

}
