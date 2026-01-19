// THIRDPARTY. https://github.com/lbownik/primitive-json

package org.xipki.util.codec.json;

//------------------------------------------------------------------------------
//Copyright 2014 Lukasz Bownik
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
//-----------------------------------------------------------------------------

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * JSON parser. This class is not thread safe but can be reused for parsing
 * consecutive JSON messages one by one.
 * @author lukasz.bownik@gmail.com
 * @author Lijun Liao (xipki)
 */
public class JsonParser {

  private JsonInputStream instream;
  private int recentChar = -1;
  private char[] buffer;
  private int bufferSize;
  private int bufIndex = 0;

  /**
   * Creates a new parser.
   */
  public JsonParser(JsonInputStream instream) {
    this(instream, 16);
  }

  /**
   * Creates a new parser.
   *
   * @param initialBufferSize
   *    initial internal buffer size for string values.
   *    Setting this parameter to a predicted maximum string value length
   *    helps to avoid buffer reallocations while parsing. If in doubt,
   *    use 15. This parameter exists only for performance optimization
   *    purposes.
   *    This parameter exists only for performance optimization purposes.
   * @throws java.lang.IllegalArgumentException
   *     if initialBufferSize <= 0.
   */
  public JsonParser(JsonInputStream instream, int initialBufferSize) {
    this.bufferSize = Args.positive(initialBufferSize, "initialBufferSize");
    this.buffer = new char[initialBufferSize];
    this.instream = Args.notNull(instream, "instream");
  }

  public static JsonMap parseMap(byte[] bytes, boolean allowComments)
      throws CodecException {
    return parseMap(JsonInputStream.newReader(
        Args.notNull(bytes, "bytes"), allowComments));
  }

  public static JsonMap parseMap(String str, boolean allowComments)
      throws CodecException {
    return parseMap(JsonInputStream.newReader(
        Args.notNull(str, "str"), allowComments));
  }

  public static JsonMap parseMap(Path path, boolean allowComments)
      throws CodecException {
    return parseMap(JsonInputStream.newReader(
        Args.notNull(path, "path"), allowComments));
  }

  public static JsonMap parseMap(
      InputStream inputStream, boolean allowComments) throws CodecException {
    return parseMap(JsonInputStream.newReader(
        Args.notNull(inputStream, "inputStream"), allowComments));
  }

  public static JsonList parseList(byte[] bytes, boolean allowComments)
      throws CodecException {
    return parseList(JsonInputStream.newReader(
        Args.notNull(bytes, "bytes"), allowComments));
  }

  public static JsonList parseList(String str, boolean allowComments)
      throws CodecException {
    return parseList(JsonInputStream.newReader(
        Args.notNull(str, "str"), allowComments));
  }

  public static JsonList parseList(Path path, boolean allowComments)
      throws CodecException {
    return parseList(JsonInputStream.newReader(
        Args.notNull(path, "path"), allowComments));
  }

  public static JsonList parseList(
      InputStream inputStream, boolean allowComments) throws CodecException {
    return parseList(JsonInputStream.newReader(
        Args.notNull(inputStream, "inputStream"), allowComments));
  }

  private static JsonMap parseMap(JsonInputStream reader)
      throws CodecException {
    JsonParser parser = new JsonParser(reader);
    return parser.parseRootMap();
  }

  private static JsonList parseList(JsonInputStream reader)
      throws CodecException {
    JsonParser parser = new JsonParser(reader);
    return parser.parseRootList();
  }

  public void close() {
    if (instream != null) {
      instream.close();
      instream = null;
    }
  }

  private JsonMap parseRootMap()
      throws CodecException {
    try {
      int currentChar = consumeWhitespace(read());
      if (currentChar == '{') {
        return parseMap();
      } else {
        throw buildUnexpected(currentChar);
      }
    } finally {
      this.instream.close();
      this.instream = null;
    }
  }

  private JsonList parseRootList() throws CodecException {
    try {
      int currentChar = consumeWhitespace(read());
      if (currentChar == '[') {
        return parseList();
      } else {
        throw buildUnexpected(currentChar);
      }
    } finally {
      this.instream.close();
      this.instream = null;
    }
  }

  private Object parseValue(int currentChar) throws CodecException {
    switch (currentChar) {
      case '"':
        return parseString();
      case '{': {
        JsonMap o = parseMap();
        this.recentChar = consumeWhitespace(read());
        return o;
      }
      case '[': {
        JsonList o = parseList();
        this.recentChar = consumeWhitespace(read());
        return o;
      }
      case 't':
        return parseTrue();
      case 'f':
        return parseFalse();
      case 'n':
        return parseNull();
      default:
        if (currentChar == '-' || (currentChar >= '0' && currentChar <= '9')) {
          return parseNumber(currentChar);
        }
        throw buildUnexpected(currentChar);
    }
  }

  private void expect(char expectedChar) throws CodecException {
    int chr = read();
    if (chr == -1) {
      throw new CodecException.CodecIOException("EOF reached");
    }

    if (chr != expectedChar) {
      throw buildUnexpected(chr);
    }
  }

  private int expectEndOfValue() throws CodecException {
    int chr = read();
    if (!isEndOfValue(chr)) {
      throw buildUnexpected(chr);
    }
    return chr;
  }

  private Boolean parseTrue() throws CodecException {
    expect('r');
    expect('u');
    expect('e');
    this.recentChar = expectEndOfValue();

    return Boolean.TRUE;
  }

  private Boolean parseFalse() throws CodecException {
    expect('a');
    expect('l');
    expect('s');
    expect('e');
    this.recentChar = expectEndOfValue();

    return Boolean.FALSE;
  }

  private Object parseNull() throws CodecException {
    expect('u');
    expect('l');
    expect('l');
    this.recentChar = expectEndOfValue();

    return null;
  }

  private JsonMap parseMap() throws CodecException {
    JsonMap ret = new JsonMap();

    int currentChar = consumeWhitespace(read());
    while (currentChar != '}') {
      if (currentChar != '"') {
        throw buildUnexpected(currentChar);
      }

      String key = parseString();

      currentChar = consumeWhitespace(this.recentChar);
      if (currentChar != ':') {
        throw buildUnexpected(currentChar);
      }

      currentChar = consumeWhitespace(read());
      Object v = parseValue(currentChar);
      if (v != null) {
        ret.putObject(key, v);
      }

      currentChar = consumeWhitespace(this.recentChar);
      if (currentChar == ',') {
        currentChar = consumeWhitespace(read());
      }
    }
    return ret;
  }

  private JsonList parseList() throws CodecException {
    JsonList result = new JsonList();

    int currentChar = consumeWhitespace(read());
    if (currentChar != ']') {
      result.addObject(parseValue(currentChar));
      currentChar = consumeWhitespace(this.recentChar);
      while (currentChar != ']') {
        if (currentChar == ',') {
          currentChar = consumeWhitespace(read());
        } else {
          throw buildUnexpected(currentChar);
        }
        result.addObject(parseValue(currentChar));
        currentChar = consumeWhitespace(this.recentChar);
      }
    }
    return result;
  }

  private Object parseNumber(int currentChar) throws CodecException {
    int signum = 1;
    long integer = 0;
    if (currentChar == '-') {
      signum = -1;
      currentChar = read();
      if (currentChar == -1) {
        throw new CodecException.CodecIOException("EOF reached");
      }

      if (currentChar == '.') {
        throw buildUnexpected(currentChar);
      }

      if (isEndOfValue(currentChar)) {
        throw buildUnexpected(currentChar);
      }
    }

    while (isDigit(currentChar)) {
      integer = 10 * integer + (currentChar - '0');
      currentChar = read();
    }

    if (isEndOfValue(currentChar)) {
      // integer - no exponent
      this.recentChar = currentChar;
      return integer * signum;
    } else if (currentChar == '.') {
      // floating point
      currentChar = read();
      if (currentChar == -1) {
        throw new CodecException.CodecIOException("EOF reached");
      }

      if (!isDigit(currentChar)) {
        throw buildUnexpected(currentChar);
      }

      double decimal = 0.1 * (currentChar - '0');
      double factor = 0.01;
      currentChar = read();
      while (isDigit(currentChar)) {
        decimal += factor * (currentChar - '0');
        factor /= 10;
        currentChar = read();
      }

      if (currentChar == 'e' | currentChar == 'E') {
        // floating point with exponent
        currentChar = read();
        int expSignum = 1;
        if (currentChar == '-') {
          expSignum = -1;
          currentChar = read();
        }

        if (currentChar == '+') {
          currentChar = read();
        }

        if (currentChar == -1) {
          throw new CodecException.CodecIOException("EOF reached");
        }

        if (!isDigit(currentChar)) {
          throw buildUnexpected(currentChar);
        }

        long exponent = (currentChar - '0');
        currentChar = read();
        while (isDigit(currentChar)) {
          exponent = 10 * exponent + (currentChar - '0');
          currentChar = read();
        }

        if (isEndOfValue(currentChar)) {
          this.recentChar = currentChar;
          if (expSignum > 0) {
            return (integer + decimal) * signum * pow(exponent);
          } else {
            return (integer + decimal) * signum / pow(exponent);
          }
        }
      } else {
        // floating point without exponent
        if (isEndOfValue(currentChar)) {
          this.recentChar = currentChar;
          return (integer + decimal) * signum;
        }
      }
      throw buildUnexpected(currentChar);
    } else if (currentChar == 'e' | currentChar == 'E') {
      // integer or float with exponent
      currentChar = read();
      int expSignum = 1;
      if (currentChar == '+') {
        currentChar = read();
      }
      if (currentChar == '-') {
        expSignum = -1;
        currentChar = read();
      }
      if (currentChar == -1) {
        throw new CodecException.CodecIOException("EOF reached");
      }
      if (!isDigit(currentChar)) {
        throw buildUnexpected(currentChar);
      }
      long exponent = (currentChar - '0');
      currentChar = read();

      while (isDigit(currentChar)) {
        exponent = 10 * exponent + (currentChar - '0');
        currentChar = read();
      }
      if (isEndOfValue(currentChar)) {
        this.recentChar = currentChar;
        if (expSignum > 0) {
          return integer * pow(exponent) * signum;
        } else {
          if (exponent == 0) {
            return integer * signum;
          } else {
            return integer * 1.0 / pow(exponent) * signum;
          }
        }
      }
    }
    return null;
  }

  private static long pow(long exp) {
    long result = 1;
    int base = 10;
    while (exp != 0) {
      if ((exp & 1) != 0) {
        result *= base;
      }

      exp >>= 1;
      base *= base;
    }
    return result;
  }

  private String parseString() throws CodecException {
    this.bufIndex = 0;
    int currentChar;
    loop:
    for (;;) {
      currentChar = read();
      switch (currentChar) {
        case -1:
          throw new CodecException.CodecIOException("EOF reached");
        case '"':
          break loop;
        case '\\':
          parseEscapedCharacter();
          break;
        default:
          append((char) currentChar);
          break;
      }
    }
    this.recentChar = read();
    return this.bufIndex > 0 ? new String(this.buffer, 0, this.bufIndex) : "";
  }

  private void parseEscapedCharacter() throws CodecException {
    int currentChar = read();
    switch (currentChar) {
      case -1:
        throw new CodecException.CodecIOException("EOF reached");
      case '\\':
        append('\\');
        break;
      case '"':
        append('\"');
        break;
      case 'b':
        append('\b');
        break;
      case 'f':
        append('\f');
        break;
      case 'n':
        append('\n');
        break;
      case 'r':
        append('\r');
        break;
      case 'u':
        parseHexadecimalCharacter();
        break;
      default:
        throw buildUnexpected((char) currentChar);
    }
  }

  private void parseHexadecimalCharacter() throws CodecException {
    int chr = 0;
    for (int i = 0; i < 4; ++i) {
      chr <<= 4;
      int currentChar = read();
      if (currentChar >= '0' & currentChar <= '9') {
        chr += (currentChar - '0');
      } else if (currentChar >= 'A' & currentChar <= 'F') {
        chr += (10 + (currentChar - 'A'));
      } else if (currentChar >= 'a' & currentChar <= 'f') {
        chr += (10 + (currentChar - 'a'));
      } else if (currentChar == -1) {
        throw new CodecException.CodecIOException("EOF reached");
      } else {
        throw buildUnexpected(currentChar);
      }
    }

    append((char) chr);
  }

  private CodecException.UnexpectedCharException buildUnexpected(int chr) {
    return new CodecException.UnexpectedCharException(
        this.instream.getPosition(), (char) chr);
  }

  private static boolean isDigit(int chr) {
    return chr >= '0' & chr <= '9';
  }

  private int consumeWhitespace(int chr) throws CodecException {
    while (chr == ' ' | chr == '\b' | chr == '\f' | chr == '\n'
        | chr == '\r' | chr == '\t') {
     chr = read();
    }

    if (chr == -1) {
      throw new CodecException.CodecIOException("EOF reached");
    }

    return chr;
  }

  private static boolean isEndOfValue(int chr) {
    return chr == -1 | chr == ' ' | chr == '\t' | chr == '\n' | chr == '\r'
      | chr == ']' | chr == '}' | chr == ',' | chr == ':';
  }

  private void append(char chr) {
    if (bufIndex == bufferSize) {
      bufferSize *= 2;
      buffer = Arrays.copyOf(buffer, bufferSize);
    }

    buffer[bufIndex++] = chr;
  }

  private int read() throws CodecException {
    return instream.read();
  }

}
