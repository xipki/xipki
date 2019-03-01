/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ConfPairs {

  private static final char BACKSLASH = '\\';

  private static class Unmodifiable extends ConfPairs {

    private ConfPairs underlying;

    private Unmodifiable(ConfPairs underlying) {
      this.underlying = underlying;
    }

    @Override
    public String value(String name) {
      return underlying.value(name);
    }

    @Override
    public Set<String> names() {
      return underlying.names();
    }

    @Override
    public String getEncoded() {
      return underlying.getEncoded();
    }

    @Override
    public String toString() {
      return underlying.toString();
    }

    @Override
    public int hashCode() {
      return underlying.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (obj instanceof Unmodifiable) {
        return underlying.equals(((Unmodifiable) obj).underlying);
      } else if (obj instanceof ConfPairs) {
        return underlying.equals((ConfPairs) obj);
      } else {
        return underlying.equals(obj);
      }
    }

    @Override
    public ConfPairs unmodifiable() {
      return this;
    }

    @Override
    public void putPair(String name, String value) {
      throw new UnsupportedOperationException("putPair() is not supported");
    }

    @Override
    public void removePair(String name) {
      throw new UnsupportedOperationException("removePair() is not supported");
    }

  }

  public static final char NAME_TERM = '=';

  public static final char TOKEN_TERM = ',';

  private final Map<String, String> pairs = new HashMap<>();

  public ConfPairs() {
  }

  public ConfPairs(String name, String value) {
    putPair(name, value);
  }

  public ConfPairs(Map<String, ? extends Object> pairs) {
    for (String name : pairs.keySet()) {
      Object value = pairs.get(name);
      putPair(name, value == null ? null : value.toString());
    }
  }

  public ConfPairs(String confPairs) {
    if (StringUtil.isBlank(confPairs)) {
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

  public void putPair(String name, String value) {
    Args.notBlank(name, "name");
    Args.notNull(value, "value");

    char ch = name.charAt(0);
    if (ch >= '0' && ch <= '9') {
      throw new IllegalArgumentException("name begin with " + ch);
    }
    pairs.put(name, value);
  }

  public void removePair(String name) {
    Args.notBlank(name, "name");
    pairs.remove(name);
  }

  public String value(String name) {
    Args.notBlank(name, "name");
    return pairs.get(name);
  }

  public Set<String> names() {
    return Collections.unmodifiableSet(pairs.keySet());
  }

  public Map<String, String> asMap() {
    return Collections.unmodifiableMap(pairs);
  }

  public String getEncoded() {
    StringBuilder sb = new StringBuilder();
    List<String> names = new LinkedList<>();
    for (String name : pairs.keySet()) {
      String value = pairs.get(name);
      if (value.length() <= 100) {
        names.add(name);
      }
    }
    Collections.sort(names);

    for (String name : pairs.keySet()) {
      if (!names.contains(name)) {
        names.add(name);
      }
    }

    for (String name : names) {
      String value = pairs.get(name);
      sb.append(encodeNameOrValue(name));
      sb.append(NAME_TERM);
      if (value != null) {
        sb.append(encodeNameOrValue(value));
      }
      sb.append(TOKEN_TERM);
    }

    if (sb.length() > 0) {
      sb.deleteCharAt(sb.length() - 1);
    }
    return sb.toString();
  } // method getEncoded

  @Override
  public String toString() {
    return getEncoded();
  }

  @Override
  public int hashCode() {
    return getEncoded().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof ConfPairs)) {
      return false;
    }

    ConfPairs other = (ConfPairs) obj;
    Set<String> thisNames = names();
    Set<String> otherNames = other.names();
    if (!thisNames.equals(otherNames)) {
      return false;
    }

    for (String name : thisNames) {
      if (!CompareUtil.equalsObject(value(name), other.value(name))) {
        return false;
      }
    }

    return true;
  }

  private static String encodeNameOrValue(String str) {
    if (str.indexOf(NAME_TERM) == -1 && str.indexOf(TOKEN_TERM) == -1) {
      return str;
    }

    final int n = str.length();
    StringBuilder sb = new StringBuilder(n + 1);
    for (int i = 0; i < n; i++) {
      char ch = str.charAt(i);
      if (ch == NAME_TERM || ch == TOKEN_TERM) {
        sb.append(BACKSLASH);
      }
      sb.append(ch);
    }
    return sb.toString();
  }

  public ConfPairs unmodifiable() {
    return new Unmodifiable(this);
  }

}
