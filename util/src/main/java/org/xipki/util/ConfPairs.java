// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.util.*;
import java.util.Map.Entry;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Container of name-value pairs.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ConfPairs {

  private static final char BACKSLASH = '\\';

  private static class Unmodifiable extends ConfPairs {

    private final ConfPairs underlying;

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
      } else if (obj instanceof ConfPairs){
        return underlying.equals(obj);
      } else {
        return false;
      }
    }

    @Override
    public ConfPairs unmodifiable() {
      return this;
    }

    @Override
    public ConfPairs putPair(String name, String value) {
      throw new UnsupportedOperationException("putPair() is not supported");
    }

    @Override
    public void removePair(String name) {
      throw new UnsupportedOperationException("removePair() is not supported");
    }

    @Override
    public Map<String, String> asMap() {
      return underlying.asMap();
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

  public ConfPairs(Map<String, ?> pairs) {
    if (pairs == null) {
      return;
    }

    for (Entry<String, ?> entry : pairs.entrySet()) {
      Object value = entry.getValue();
      String str = null;
      if (value instanceof String) {
        str = (String) value;
      } else if (value instanceof Double) {
        double d = (double) value;
        if (d == (long) d) {
          str = Long.toString((long) d);
        }
      } else if (value instanceof Float) {
        float d = (float) value;
        if (d == (int) d) {
          str = Integer.toString((int) d);
        }
      }

      if (str == null && value != null) {
        str = value.toString();
      }

      putPair(entry.getKey(), str);
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

  public boolean isEmpty() {
    return pairs.isEmpty();
  }

  public ConfPairs putPair(String name, String value) {
    notBlank(name, "name");
    notNull(value, "value");

    char ch = name.charAt(0);
    if (ch >= '0' && ch <= '9') {
      throw new IllegalArgumentException("name begin with " + ch);
    }
    pairs.put(name, value);
    return this;
  }

  public void removePair(String name) {
    pairs.remove(notBlank(name, "name"));
  }

  public String value(String name) {
    return pairs.get(notBlank(name, "name"));
  }

  public String value(String name, String defaultValue) {
    String value = pairs.get(notBlank(name, "name"));
    return value == null ? defaultValue : value;
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
    for (Entry<String, String> entry : pairs.entrySet()) {
      String value = entry.getValue();
      if (value.length() <= 100) {
        names.add(entry.getKey());
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

  public String toStringOmitSensitive(String... nameKeywords) {
    return toStringOmitSensitive(Arrays.asList(nameKeywords), null);
  }

  public String toStringOmitSensitive(Collection<String> nameKeywords, Collection<String> ignoreList) {
    Set<String> names = new HashSet<>();
    for (Entry<String, String> entry : pairs.entrySet()) {
      String lname = entry.getKey().toLowerCase();
      boolean sensitive = contains(lname, nameKeywords);
      if (sensitive) {
        sensitive = ignoreList == null || !contains(lname, ignoreList);
      }

      if (sensitive) {
        names.add(entry.getKey());
      }
    }

    if (names.isEmpty()) {
      return getEncoded();
    }

    try {
      for (Entry<String, String> entry : pairs.entrySet()) {
        String name = entry.getKey();
        if (names.contains(name)) {
          pairs.put(name, "<sensitive>");
        }
      }
      return new ConfPairs(pairs).getEncoded();
    } catch (Exception ex) {
      return getEncoded();
    }
  }

  private static boolean contains(String name, Collection<String> list) {
    for (String m : list) {
      if (name.contains(m.toLowerCase(Locale.ROOT))) {
        return true;
      }
    }
    return false;
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
