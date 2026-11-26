// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.util.*;
import java.util.regex.Pattern;
import org.xipki.codec.json.JsonParser;

/**
 * Guards strict HTTP JSON syntax before XiPKI decoding; retains member names lost for nulls.
 *
 * @author palos
 */
final class JsonSyntax {
  record Shape(Map<String, Shape> fields, List<Shape> items) {}

  private static final Shape SCALAR = new Shape(null, null);
  private static final Pattern NUMBER =
      Pattern.compile("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");
  private final String text;
  private int position;

  private JsonSyntax(String text) {
    this.text = Objects.requireNonNull(text);
  }

  static Shape validate(String text) {
    JsonSyntax syntax = new JsonSyntax(text);
    Shape result = syntax.value(0);
    syntax.space();
    if (syntax.position != text.length()) {
      throw invalid();
    }
    return result;
  }

  private Shape value(int depth) {
    if (depth > 128) {
      throw invalid();
    }
    space();
    char c = peek();
    if (c == '{') {
      position++;
      space();
      Map<String, Shape> fields = new LinkedHashMap<>();
      if (take('}')) {
        return new Shape(fields, null);
      }
      do {
        space();
        int start = position;
        string();
        String key;
        try {
          key =
              JsonParser.parseMap("{" + text.substring(start, position) + ":true}", false)
                  .getKeys()
                  .get(0);
        } catch (Exception ex) {
          throw invalid();
        }
        space();
        require(':');
        Shape child = value(depth + 1);
        if (fields.putIfAbsent(key, child) != null) {
          throw invalid();
        }
        space();
        if (take('}')) {
          return new Shape(fields, null);
        }
        require(',');
      } while (true);
    }
    if (c == '[') {
      position++;
      space();
      List<Shape> items = new ArrayList<>();
      if (take(']')) {
        return new Shape(null, items);
      }
      do {
        items.add(value(depth + 1));
        space();
        if (take(']')) {
          return new Shape(null, items);
        }
        require(',');
      } while (true);
    }
    if (c == '"') {
      string();
      return SCALAR;
    }
    for (String literal : List.of("true", "false", "null")) {
      if (text.startsWith(literal, position)) {
        position += literal.length();
        return SCALAR;
      }
    }
    var matcher = NUMBER.matcher(text);
    matcher.region(position, text.length());
    if (!matcher.lookingAt()) {
      throw invalid();
    }
    position = matcher.end();
    return SCALAR;
  }

  private void string() {
    require('"');
    while (position < text.length()) {
      char c = text.charAt(position++);
      if (c == '"') {
        return;
      }
      if (c < 0x20) {
        throw invalid();
      }
      if (c == '\\') {
        c = peek();
        position++;
        if (c == 'u') {
          for (int i = 0; i < 4; i++) {
            if (position >= text.length() || Character.digit(text.charAt(position++), 16) < 0) {
              throw invalid();
            }
          }
        } else if ("\"\\/bfnrt".indexOf(c) < 0) {
          throw invalid();
        }
      }
    }
    throw invalid();
  }

  private char peek() {
    if (position >= text.length()) {
      throw invalid();
    }
    return text.charAt(position);
  }

  private void space() {
    while (position < text.length() && " \t\r\n".indexOf(text.charAt(position)) >= 0) {
      position++;
    }
  }

  private boolean take(char c) {
    if (position < text.length() && text.charAt(position) == c) {
      position++;
      return true;
    }
    return false;
  }

  private void require(char c) {
    if (!take(c)) {
      throw invalid();
    }
  }

  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("Malformed JSON request");
  }
}
