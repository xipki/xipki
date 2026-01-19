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

import org.xipki.util.codec.Args;
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
public class JsonTxtBuilder {

  private static class MyAppendable implements Appendable {

    private final int maxCharsPerLine;

    private final StringBuilder sb = new StringBuilder();

    private String line = "";

    private int lineNo = 0;

    MyAppendable(int maxCharsPerLine) {
      this.maxCharsPerLine = maxCharsPerLine;
    }

    @Override
    public Appendable append(CharSequence csq) throws IOException {
      return append(csq, 0, csq.length());
    }

    @Override
    public Appendable append(CharSequence csq, int start, int end)
        throws IOException {
      for (int i = start; i < end; i++) {
        append(csq.charAt(i));
      }
      return this;
    }

    private boolean manualLineBreak = false;

    @Override
    public Appendable append(char c) throws IOException {
      if (c == '\n') {
        if (!line.isEmpty()) {
          sb.append(line);
          line = "";
        }

        if (!manualLineBreak) {
          lineNo++;
          sb.append(c);
        } else {
          manualLineBreak = false;
        }
      } else {
        line += c;
        manualLineBreak = false;
        if (line.length() >= maxCharsPerLine) {
          sb.append(line);
          lineNo++;
          sb.append("\n");
          line = "";
          manualLineBreak = true;
        }
      }
      return this;
    }

    public String doFinal() {
      if (!line.isEmpty()) {
        sb.append(line);
      }
      return sb.toString();
    }
  }

  private final String indent;

  private final int maxCharsPerLine;

  private final int[] buf = new int[22];

  public JsonTxtBuilder(int maxCharsPerLine) {
    this(null, maxCharsPerLine);
  }

  public JsonTxtBuilder(String indent, int maxCharsPerLine) {
    this.maxCharsPerLine = Args.min(maxCharsPerLine,
        "maxCharsPerLine", 40);
    this.indent = (indent == null) ? "  " : indent;
  }

  public String toJson(JsonMap root) {
    MyAppendable builder = new MyAppendable(maxCharsPerLine);
    try {
      writeMap(root, builder, 0);
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
    return builder.doFinal();
   }

  public String toJson(JsonList root) {
    MyAppendable builder = new MyAppendable(maxCharsPerLine);
    try {
      writeList(root, builder, 0);
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
    return builder.doFinal();
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
    if (size > 0) {
      append(out, "\n");
      for (int i = 0; i < size; ++i) {
        Object v = value.getAt(i);
        appendIndent(out, level + 1);
        writeValue(v, out, level + 1);
        if (i != size - 1) {
          append(out, ",\n");
        }
      }
    }

    append(out, '\n');
    appendIndent(out, level);
    append(out, ']');
  }

  private void writeMap(JsonMap value, Appendable out, int level)
      throws CodecException {
    append(out, "{\n");

    List<String> keys = value.getKeys();
    boolean first = true;
    for (String key : keys) {
      if (first) {
        first = false;
      } else {
        append(out, ",\n");
      }

      appendIndent(out, level + 1);
      writeKey(key, out);
      writeValue(value.getObject(key), out, level + 1);
    }

    if (!keys.isEmpty()) {
      append(out, '\n');
    }
    appendIndent(out, level);
    append(out, "}");
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
        write(d, out);
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
    append(out, "\": ");
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
    for (int i = 0; i < level; i++) {
      append(out, indent);
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
