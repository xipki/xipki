// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Container of name-value pairs.
 *
 * @author Lijun Liao (xipki)
 */

class ConfPairs {

  private static final char BACKSLASH = '\\';

  public static final char NAME_TERM = '=';

  public static final char TOKEN_TERM = ',';

  private final Map<String, String> pairs = new HashMap<>();

  ConfPairs(String confPairs) {
    if (Args.isBlank(confPairs)) {
      return;
    }

    int len = confPairs.length();
    List<String> tokens = new LinkedList<>();

    StringBuilder tokenBuilder = new StringBuilder();

    for (int i = 0; i < len;) {
      char ch = confPairs.charAt(i);
      if (TOKEN_TERM == ch) {
        if (tokenBuilder.length() > 0) {
          tokens.add(tokenBuilder.toString());
        }
        // reset tokenBuilder
        tokenBuilder = new StringBuilder();
        i++;
        continue;
      }

      if (BACKSLASH == ch) {
        if (i == len - 1) {
          throw new IllegalArgumentException("invalid ConfPairs '" + confPairs + "'");
        }

        tokenBuilder.append(ch);
        ch = confPairs.charAt(i + 1);
        i++;
      }

      tokenBuilder.append(ch);
      i++;
    }

    if (tokenBuilder.length() > 0) {
      tokens.add(tokenBuilder.toString());
    }

    for (String token : tokens) {
      int termPosition = -1;
      len = token.length();
      for (int i = 0; i < len;) {
        char ch = token.charAt(i);
        if (ch == NAME_TERM) {
          termPosition = i;
          break;
        }

        if (BACKSLASH == ch) {
          if (i == len - 1) {
            throw new IllegalArgumentException("invalid ConfPairs '" + confPairs + "'");
          }

          i += 2;
        } else {
          i++;
        }
      }

      if (termPosition < 1) {
        throw new IllegalArgumentException("invalid ConfPair '" + token + "'");
      }

      tokenBuilder = new StringBuilder();
      for (int i = 0; i < termPosition;) {
        char ch = token.charAt(i);
        if (BACKSLASH == ch) {
          if (i == termPosition - 1) {
            throw new IllegalArgumentException("invalid ConfPair '" + confPairs + "'");
          }

          i += 2;
        } else {
          tokenBuilder.append(ch);
          i++;
        }
      }

      String name = tokenBuilder.toString();

      tokenBuilder = new StringBuilder();
      for (int i = termPosition + 1; i < len;) {
        char ch = token.charAt(i);
        if (BACKSLASH == ch) {
          if (i == len - 1) {
            throw new IllegalArgumentException("invalid ConfPair '" + confPairs + "'");
          }

          ch = token.charAt(i + 1);
          i++;
        }

        tokenBuilder.append(ch);
        i++;
      }

      String value = tokenBuilder.toString();
      pairs.put(name, value);
    }
  } // constructor

  String value(String name) {
    return pairs.get(Args.notBlank(name, "name"));
  }

}
