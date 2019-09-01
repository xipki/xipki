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

package org.xipki.security.cmp;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.util.Args;

/**
 * Specifies utf8Pairs defined in RFC4211.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpUtf8Pairs {

  public static final String KEY_CERTPROFILE = "certprofile";

  public static final String KEY_NOTBEFORE = "notbefore";

  public static final String KEY_NOTAFTER = "notafter";

  public static final String KEY_CA_GENERATE_KEYPAIR = "ca-generate-keypair";

  private static final char NAME_TERM = '?';

  private static final char TOKEN_TERM = '%';

  private final Map<String, String> pairs = new HashMap<>();

  public CmpUtf8Pairs(String name, String value) {
    putUtf8Pair(name, value);
  }

  public CmpUtf8Pairs() {
  }

  public CmpUtf8Pairs(String encodedCmpUtf8Pairs) {
    String encoded = Args.notBlank(encodedCmpUtf8Pairs, "encodedCmpUtf8Pairs");
    // remove the ending '%'-symbols
    while (encoded.charAt(encoded.length() - 1) == TOKEN_TERM) {
      encoded = encoded.substring(0, encoded.length() - 1);
    }

    // find the position of terminators
    List<Integer> positions = new LinkedList<>();

    int idx = 1;
    int len = encoded.length();
    while (idx < len) {
      char ch = encoded.charAt(idx++);
      if (ch == TOKEN_TERM) {
        char ch2 = encoded.charAt(idx);
        if (ch2 < '0' || ch2 > '9') {
          positions.add(idx - 1);
        }
      }
    }
    positions.add(encoded.length());

    // parse the token
    int beginIndex = 0;
    for (int i = 0; i < positions.size(); i++) {
      int endIndex = positions.get(i);
      String token = encoded.substring(beginIndex, endIndex);

      int sepIdx = token.indexOf(NAME_TERM);
      if (sepIdx == -1 || sepIdx == token.length() - 1) {
        throw new IllegalArgumentException("invalid token: " + token);
      }
      String name = token.substring(0, sepIdx);
      name = decodeNameOrValue(name);
      String value = token.substring(sepIdx + 1);
      value = decodeNameOrValue(value);
      pairs.put(name, value);

      beginIndex = endIndex + 1;
    }
  } // constructor

  public final void putUtf8Pair(String name, String value) {
    Args.notNull(name, "name");
    Args.notNull(value, "value");

    char ch = name.charAt(0);
    if (ch >= '0' && ch <= '9') {
      throw new IllegalArgumentException("name may not begin with " + ch);
    }
    pairs.put(name, value);
  }

  public void removeUtf8Pair(String name) {
    Args.notNull(name, "name");
    pairs.remove(name);
  }

  public String value(String name) {
    Args.notNull(name, "name");
    return pairs.get(name);
  }

  public Set<String> names() {
    return Collections.unmodifiableSet(pairs.keySet());
  }

  public String encoded() {
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

    return sb.toString();
  } // method encoded

  @Override
  public String toString() {
    return encoded();
  }

  @Override
  public int hashCode() {
    return encoded().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CmpUtf8Pairs)) {
      return false;
    }

    CmpUtf8Pairs objB = (CmpUtf8Pairs) obj;
    return pairs.equals(objB.pairs);
  }

  private static String encodeNameOrValue(String str) {
    String tmpStr = str;
    if (tmpStr.indexOf("%") != -1) {
      tmpStr = tmpStr.replaceAll("%", "%25");
    }

    if (tmpStr.indexOf("?") != -1) {
      tmpStr = tmpStr.replaceAll("\\?", "%3f");
    }

    return tmpStr;
  }

  private static String decodeNameOrValue(String str) {
    int idx = str.indexOf(TOKEN_TERM);
    if (idx == -1) {
      return str;
    }

    StringBuilder newS = new StringBuilder();

    for (int i = 0; i < str.length();) {
      char ch = str.charAt(i);
      if (ch != TOKEN_TERM) {
        newS.append(ch);
        i++;
      } else {
        if (i + 3 <= str.length()) {
          String hex = str.substring(i + 1, i + 3);
          ch = (char) Byte.parseByte(hex, 16);
          newS.append(ch);
          i += 3;
        } else {
          newS.append(str.substring(i));
          break;
        }
      }
    }

    return newS.toString();
  } // method decodeNameOrValue

}
