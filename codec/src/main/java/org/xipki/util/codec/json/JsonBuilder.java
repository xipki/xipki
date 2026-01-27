// THIRDPARTY. https://github.com/lbownik/primitive-json

//------------------------------------------------------------------------------
//Copyright 2014 Lukasz Bownik, Yidong Fang, Chris Nokleberg, Dave Hughes
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//------------------------------------------------------------------------------
package org.xipki.util.codec.json;

import org.xipki.util.codec.CodecException;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

/**
 * JSON builder. This class is not thread safe but can be reused for parsing
 * consecutive JSON messages one by one.
 * @author lukasz.bownik@gmail.com
 * @author Lijun Liao (xipki)
 */
public class JsonBuilder {

  private static final JsonBuilder PRETTY_BUILDER = new JsonBuilder(true);

  private static final JsonBuilder BUILDER = new JsonBuilder(false);

  private final boolean pretty;

  private final String indent;

  private final boolean withSpaceAfterKey;

  private final int[] buf = new int[22];

  /**
   * Create a generator
   */
  public JsonBuilder() {
     this(false);
  }

  /**
   * Create a generator
   */
  public JsonBuilder(boolean pretty) {
    this(pretty, null, true);
  }

  public JsonBuilder(boolean pretty, String indent, boolean withSpaceAfterKey) {
    this.pretty = pretty;
    this.indent = indent == null ? "  " : indent;
    this.withSpaceAfterKey = withSpaceAfterKey;
  }

  public static String toJson(JsonMap root) {
    return BUILDER.doToJson(root);
  }

  public static String toPrettyJson(JsonMap root) {
    return PRETTY_BUILDER.doToJson(root);
  }

  public static String toJson(JsonList root) {
    return BUILDER.doToJson(root);
  }

  public static String toPrettyJson(JsonList root) {
    return PRETTY_BUILDER.doToJson(root);
  }

  public String doToJson(JsonMap root) {
    StringBuilder builder = new StringBuilder();
    try {
      writeMap(root, builder, 0);
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
    return builder.toString();
   }

  public String doToJson(JsonList root) {
    StringBuilder builder = new StringBuilder();
    try {
      writeList(root, builder, 0);
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
    return builder.toString();
  }

  /**
   * Encode an ArrayList into JSON text and write it to out.
   *
   * @param value list.
   * @param out appendable object.
   * @throws CodecException if output error occurs.
   * @throws NullPointerException if value or out == null.
   */
  private void writeList(JsonList value, Appendable out, int level)
      throws CodecException {
    final int size = value.size();

    append(out, '[');
    boolean containsListOrMap = false;
    if (size != 0) {
      boolean wrapLongLine = pretty
          && out instanceof CharSequence
          && !value.withListOrMap();

      if (wrapLongLine) {
        int maxLineEndIndex = Math.max(40, 70 - indent.length() * level);
        int offset = ((CharSequence) out).length();
        // evaluate the length of first line's prefix: 10
        offset -= 20;

        for (int i = 0; i < size; ++i) {
          Object v = value.getAt(i);
          if (!containsListOrMap) {
            containsListOrMap =
                (v instanceof JsonMap) || (v instanceof JsonList);
          }

          writeValue(v, out, level + 1);
          if (i != size - 1) {
            append(out, ',');

            int currentOff = ((CharSequence) out).length();
            if (currentOff - offset > maxLineEndIndex) {
              append(out, '\n');
              appendIndent(out, level + 1);
              offset = currentOff;
            }
          }
        }
      } else {
        for (int i = 0; i < size; ++i) {
          Object v = value.getAt(i);
          if (!containsListOrMap) {
            containsListOrMap =
                (v instanceof JsonMap) || (v instanceof JsonList);
          }

          writeValue(v, out, level + 1);
          if (i != size - 1) {
            append(out, ',');
          }
        }
      }
    }

    if (pretty && containsListOrMap) {
      append(out, '\n');
      appendIndent(out, level);
      append(out, ']');
    } else {
      append(out, ']');
    }
  }

  private void writeMap(JsonMap value, Appendable out, int level)
      throws CodecException {
    if (pretty) {
      append(out, "{\n");
    } else {
      append(out, '{');
    }

    List<String> keys = value.getKeys();
    boolean first = true;
    for (String key : keys) {
      if (first) {
        first = false;
      } else {
        if (pretty) {
          append(out, ",\n");
        } else {
          append(out, ',');
        }
      }

      appendIndent(out, level + 1);
      writeKey(key, out);
      writeValue(value.getObject(key), out, level + 1);
    }

    if (pretty) {
      if (!keys.isEmpty()) {
        append(out, '\n');
      }
      appendIndent(out, level);
      append(out, "}");
    } else {
      append(out, '}');
    }
  }

  protected void writeValue(Object value, Appendable out, int level)
      throws CodecException {
    if (value == null) {
      append(out, "null");
      return;
    }

    if (value instanceof Double) {
      final Double d = (Double) value;
      if (d.isInfinite() | d.isNaN()) {
        append(out, "null");
      } else {
        write(d.doubleValue(), out);
      }
      return;
   }

    if (value instanceof Float) {
      final Float f = (Float) value;
      if (f.isInfinite() | f.isNaN()) {
        append(out, "null");
      } else {
        write(f.doubleValue(), out);
      }
      return;
    }

    if (value instanceof Number) {
      write(((Number) value).longValue(), out);
      return;
    }

    if (value instanceof Boolean) {
      append(out, value.toString());
      return;
    }

    if (value instanceof JsonMap) {
      writeMap((JsonMap) value, out, level);
      return;
    }

    if (value instanceof JsonList) {
      writeList((JsonList) value, out, level);
      return;
    }

    if (value instanceof Instant) {
      value = value.toString();
    }

    append(out, '\"');
    writeEscaped(value.toString(), out);
    append(out, '\"');
  }

  private void writeKey(String key, Appendable out)
      throws CodecException {
    append(out, '\"');
    writeEscaped(key, out);
    if (withSpaceAfterKey) {
      append(out, "\": ");
    } else {
      append(out, "\":");
    }
  }

  private static void writeEscaped(String s, Appendable out)
      throws CodecException {
    final int length = s.length();
    for (int i = 0; i < length; i++) {
      final char ch = s.charAt(i);
      switch (ch) {
        case '"':
          append(out, "\\\"");
          break;
        case '\\':
          append(out, "\\\\");
          break;
        case '\b':
          append(out, "\\b");
          break;
        case '\f':
          append(out, "\\f");
          break;
        case '\n':
          append(out, "\\n");
          break;
        case '\r':
          append(out, "\\r");
          break;
        default:
          append(out, ch);
      }
    }//for
  }

  private void write(long value, Appendable out)
      throws CodecException {
    if (value == 0) {
      append(out, '0');
      return;
    }

    if (value < 0) {
      append(out, '-');
      value *= -1;
    }

    final int[] buf = this.buf;
    int index = 0;
    while (value > 0) {
      buf[index++] = '0' + (int) (value % 10);
      value /= 10;
    }

    while (index > 0) {
      append(out, (char) buf[--index]);
    }
  }

  private void write(double value, Appendable out)
      throws CodecException {
    write((long) value, out);
    if (value < 0) {
      value *= -1;
    }

    double decimal = value - (long) value;
    append(out, '.');
    if (decimal == 0.0) {
      append(out, '0');
      return;
    }

    for (int i = 0; i < 14; i++) {
      decimal *= 10.0;
      append(out, (char) ('0' + (int) decimal));
      decimal -= (int) decimal;
    }
  }

  private void appendIndent(Appendable out, int level)
      throws CodecException {
    if (pretty) {
      for (int i = 0; i < level; i++) {
        append(out, indent);
      }
    }
  }

  private static void append(Appendable out, char c) throws CodecException {
    try {
      out.append(c);
    } catch (IOException e) {
      throw new CodecException.CodecIOException(e);
    }
  }

  private static void append(Appendable out, String str)
      throws CodecException {
    try {
      out.append(str);
    } catch (IOException e) {
      throw new CodecException.CodecIOException(e);
    }
  }

}
