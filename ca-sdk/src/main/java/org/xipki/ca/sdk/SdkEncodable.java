// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.codec.cbor.ByteArrayCborEncoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Sdk Encodable.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class SdkEncodable extends CborEncodable {

  protected abstract void encode0(CborEncoder encoder) throws CodecException;

  @Override
  public final void encode(CborEncoder encoder) throws CodecException {
    encode0(encoder);
  }

  public byte[] encode() throws CodecException {
    ByteArrayCborEncoder encoder = new ByteArrayCborEncoder();
    encode(encoder);
    return encoder.toByteArray();
  }

  protected static void assertArrayStart(String name, CborDecoder decoder, int size)
      throws CodecException {
    if (decoder.readNullOrArrayLength(size)) {
      throw new CodecException(name + " must not be null.");
    }
  }

  protected static String buildDecodeErrMessage(Exception ex, Class<?> clazz) {
    return "error decoding " + clazz.getName() + ": " + ex.getMessage();
  }

  /**
   * Appends "name: value" followed by a new line. Nothing is appended if value is null.
   */
  protected static StringBuilder appendField(
      StringBuilder buf, int indentLevel, String name, Object value) {
    if (value != null) {
      ToStringUtil.appendIndent(buf, indentLevel, name + ": " + value + "\n");
    }
    return buf;
  }

  /**
   * Appends "name: [v1, v2, ...]" followed by a new line. Nothing is appended if values is null.
   */
  protected static StringBuilder appendFields(
      StringBuilder buf, int indentLevel, String name, Object[] values) {
    return (values == null) ? buf : appendField(buf, indentLevel, name, Arrays.toString(values));
  }

  /**
   * Appends "name: 0x&lt;hex&gt;" followed by a new line. Nothing is appended if value is null.
   */
  protected static StringBuilder appendBigInt(
      StringBuilder buf, int indentLevel, String name, BigInteger value) {
    return (value == null) ? buf : appendField(buf, indentLevel, name, "0x" + value.toString(16));
  }

  /**
   * Appends the short byte array in one line, followed by a new line. Nothing is appended if
   * value is null.
   */
  protected static StringBuilder appendBytes(
      StringBuilder buf, int indentLevel, String name, byte[] value) {
    return (value == null) ? buf : ToStringUtil.appendHexOneLine(name, buf, indentLevel, value);
  }

  /**
   * Appends the name and, in the next lines, the long byte array, followed by a new line.
   * Nothing is appended if value is null.
   */
  protected static StringBuilder appendLongBytes(
      StringBuilder buf, int indentLevel, String name, byte[] value) {
    if (value != null) {
      ToStringUtil.appendHexWithPrefix(buf, indentLevel, value, name + ":").append("\n");
    }
    return buf;
  }

  /**
   * Appends the long byte arrays, followed by a new line. Nothing is appended if values is null.
   */
  protected static StringBuilder appendLongBytesArray(
      StringBuilder buf, int indentLevel, String name, byte[][] values) {
    if (values == null) {
      return buf;
    }

    if (values.length == 0) {
      return ToStringUtil.appendIndent(buf, indentLevel, name + ": <empty>\n");
    }

    ToStringUtil.appendIndent(buf, indentLevel, name + ":\n");
    for (int i = 0; i < values.length; i++) {
      if (values[i] == null) {
        appendField(buf, indentLevel + 1, "[" + i + "]", "null");
      } else {
        appendLongBytes(buf, indentLevel + 1, "[" + i + "]", values[i]);
      }
    }
    return buf;
  }

  /**
   * Appends the object, followed by a new line. Nothing is appended if value is null.
   */
  protected static StringBuilder appendObject(
      StringBuilder buf, int indentLevel, String name, CborEncodable value) {
    return (value == null) ? buf : value.toStringWithLineSep(buf, indentLevel, name, true);
  }

  /**
   * Appends the X.500 name in one line, followed by a new line. Nothing is appended if value is
   * null.
   */
  protected static StringBuilder appendName(
      StringBuilder buf, int indentLevel, String name, X500NameType value) {
    return (value == null) ? buf : value.toStringNoLineSep(buf, indentLevel, name, true);
  }

  /**
   * Appends the objects, followed by a new line. Nothing is appended if values is null.
   */
  protected static StringBuilder appendObjects(
      StringBuilder buf, int indentLevel, String name, CborEncodable[] values) {
    if (values == null) {
      return buf;
    }

    if (values.length == 0) {
      return ToStringUtil.appendIndent(buf, indentLevel, name + ": <empty>\n");
    }

    ToStringUtil.appendIndent(buf, indentLevel, name + ":\n");
    for (int i = 0; i < values.length; i++) {
      if (values[i] == null) {
        appendField(buf, indentLevel + 1, "[" + i + "]", "null");
      } else {
        appendObject(buf, indentLevel + 1, "[" + i + "]", values[i]);
      }
    }
    return buf;
  }

  /**
   * Removes the trailing new line, or appends "&lt;empty&gt;" if nothing has been appended
   * since startLen.
   */
  protected static StringBuilder endToString(StringBuilder buf, int indentLevel, int startLen) {
    if (buf.length() == startLen) {
      return ToStringUtil.appendIndent(buf, indentLevel, "<empty>");
    }
    return deleteLastNewLine(buf);
  }

}
