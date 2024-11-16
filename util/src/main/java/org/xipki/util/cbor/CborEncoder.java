// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 *
 * Licensed under Apache License v2.0.
 */
package org.xipki.util.cbor;

import org.xipki.util.Args;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.xipki.util.cbor.CborConstants.*;

/**
 * Provides an encoder capable of encoding data into CBOR format to a given {@link OutputStream}.
 */
public abstract class CborEncoder {

  private static final int NEG_INT_MASK = TYPE_NEGATIVE_INTEGER << 5;
  private static final BigInteger _2power64 = new BigInteger("10000000000000000", 16);

  protected abstract void write(byte b) throws IOException;

  protected abstract void write(int b) throws IOException;

  protected void write(byte[] bytes) throws IOException {
    write(bytes, 0, bytes.length);
  }

  protected abstract void write(byte[] bytes, int off, int len) throws IOException;

  /**
   * Interprets a given float-value as a half-precision float value and
   * converts it to its raw integer form, as defined in IEEE 754.
   * <p>
   * Taken from: <a href="http://stackoverflow.com/a/6162687/229140">this Stack Overflow answer</a>.
   * </p>
   *
   * @param fval the value to convert.
   * @return the raw integer representation of the given float value.
   */
  static int halfPrecisionToRawIntBits(float fval) {
    int fbits = Float.floatToIntBits(fval);
    int sign = (fbits >>> 16) & 0x8000;
    int val = (fbits & 0x7fffffff) + 0x1000;

    // might be or become NaN/Inf
    if (val >= 0x47800000) {
      if ((fbits & 0x7fffffff) >= 0x47800000) { // is or must become NaN/Inf
        if (val < 0x7f800000) {
          // was value but too large, make it +/-Inf
          return sign | 0x7c00;
        }
        return sign | 0x7c00 | (fbits & 0x007fffff) >>> 13; // keep NaN (and Inf) bits
      }
      return sign | 0x7bff; // unrounded not quite Inf
    }

    if (val >= 0x38800000) {
      // remains normalized value
      return sign | val - 0x38000000 >>> 13; // exp - 127 + 15
    }

    if (val < 0x33000000) {
      // too small for subnormal
      return sign; // becomes +/-0
    }

    val = (fbits & 0x7fffffff) >>> 23;
    // add subnormal bit, round depending on cut off and div by 2^(1-(exp-127+15)) and >> 13 | exp=0
    return sign | ((fbits & 0x7fffff | 0x800000) + (0x800000 >>> val - 102) >>> 126 - val);
  }

  /**
   * Writes the start of an indefinite-length array.
   * <p>
   * After calling this method, one is expected to write the given number of array elements, which can be of any type.
   * No length checks are performed.<p>
   * After all array elements are written, one should write a single break value to end the array,
   * see {@link #writeBreak()}.
   * </p>
   *
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeArrayStart() throws IOException {
    writeSimpleType(TYPE_ARRAY, BREAK);
  }

  /**
   * Writes the start of a definite-length array.
   * <p>
   * After calling this method, one is expected to write the given number of array elements, which can be of any type.
   * No length checks are performed.
   * </p>
   *
   * @param length the number of array elements to write, should &gt;= 0.
   * @throws IllegalArgumentException in case the given length was negative;
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeArrayStart(int length) throws IOException {
    Args.notNegative(length, "array-length");
    writeType(TYPE_ARRAY, length);
  }

  /**
   * Writes a boolean value in canonical CBOR format.
   *
   * @param value the boolean to write.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeBoolean(boolean value) throws IOException {
    writeSimpleType(TYPE_FLOAT_SIMPLE, value ? TRUE : FALSE);
  }

  /**
   * Writes a "break" stop-value in canonical CBOR format.
   *
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeBreak() throws IOException {
    writeSimpleType(TYPE_FLOAT_SIMPLE, BREAK);
  }

  /**
   * Writes a byte string in canonical CBOR-format.
   *
   * @param bytes the byte string to write, can be <code>null</code> in which case a null is written.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeByteString(byte[] bytes) throws IOException {
    if (bytes == null) {
      writeNull();
    } else {
      writeString(TYPE_BYTE_STRING, bytes);
    }
  }

  public void writeByteString(byte[] bytes, int off, int len) throws IOException {
    writeString(TYPE_BYTE_STRING, bytes, off, len);
  }

  /**
   * Writes the start of an indefinite-length byte string.
   * <p>
   * After calling this method, one is expected to write the given number of string parts. No length checks are
   * performed.
   * <p>
   * After all string parts are written, one should write a single break value to end the string,
   * see {@link #writeBreak()}.
   * </p>
   *
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeByteStringStart() throws IOException {
    writeSimpleType(TYPE_BYTE_STRING, BREAK);
  }

  /**
   * Writes a double-precision float value in canonical CBOR format.
   *
   * @param value the value to write, values from {@link Double#MIN_VALUE} to {@link Double#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeDouble(double value) throws IOException {
    writeUInt64(TYPE_FLOAT_SIMPLE << 5, Double.doubleToRawLongBits(value));
  }

  /**
   * Writes a single-precision float value in canonical CBOR format.
   *
   * @param value the value to write, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeFloat(float value) throws IOException {
    writeUInt32(TYPE_FLOAT_SIMPLE << 5, Float.floatToRawIntBits(value));
  }

  /**
   * Writes a half-precision float value in canonical CBOR format.
   *
   * @param value the value to write, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeHalfPrecisionFloat(float value) throws IOException {
    writeUInt16(TYPE_FLOAT_SIMPLE << 5, halfPrecisionToRawIntBits(value));
  }

  public void writeUint(BigInteger value) throws IOException {
    int bitLength = value.bitLength();
    if (value.signum() == -1 || bitLength > 64) {
      throw new IllegalArgumentException("value not in the range [0, 2^64 - 1]");
    }

    if (bitLength <= 63) {
      writeInt(value.longValueExact());
    } else {
      writeUInt64(0, value.longValue());
    }
  }

  /**
   * Writes a signed or unsigned integer value in canonical CBOR format, that is, tries to encode it in a little
   * bytes as possible.
   *
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeInt(long value) throws IOException {
    // extends the sign over all bits...
    long sign = value >> 63;
    // in case value is negative, this bit should be set...
    int mt = (int) (sign & NEG_INT_MASK);
    // complement negative value...
    value = (sign ^ value);

    writeUInt(mt, value);
  }

  /**
   * Writes a signed or unsigned 16-bit integer value in CBOR format.
   *
   * @param value the value to write, values from [-65536..65535] are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeInt16(int value) throws IOException {
    // extends the sign over all bits...
    int sign = value >> 31;
    // in case value is negative, this bit should be set...
    int mt = (sign & NEG_INT_MASK);
    // complement negative value...
    writeUInt16(mt, (sign ^ value) & 0xffff);
  }

  /**
   * Writes a signed or unsigned 32-bit integer value in CBOR format.
   *
   * @param value the value to write, values in the range [-4294967296..4294967295] are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeInt32(long value) throws IOException {
    // extends the sign over all bits...
    long sign = value >> 63;
    // in case value is negative, this bit should be set...
    int mt = (int) (sign & NEG_INT_MASK);
    // complement negative value...
    writeUInt32(mt, (int) ((sign ^ value) & 0xffffffffL));
  }

  /**
   * Writes a signed or unsigned 64-bit integer value in CBOR format.
   *
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeInt64(long value) throws IOException {
    // extends the sign over all bits...
    long sign = value >> 63;
    // in case value is negative, this bit should be set...
    int mt = (int) (sign & NEG_INT_MASK);
    // complement negative value...
    writeUInt64(mt, sign ^ value);
  }

  public void writeNegInt64(BigInteger value) throws IOException {
    int signum = value.signum();
    if (signum != -1) {
      throw new IllegalArgumentException("value not in the range [-2^64, -1]");
    }

    value = value.negate();
    if (value.compareTo(_2power64) > 0) {
      throw new IllegalArgumentException("value not in the range [-2^64, -1]");
    }

    write(0x3B);
    byte[] bytes = value.toByteArray();
    int len = bytes.length;
    if (len == 9) {
      write(bytes, 1, 8);
    } else if (len == 8) {
      write(bytes, 0, len);
    } else if (len < 8) {
      byte[] prefix = new byte[8 - len];
      write(prefix);
      write(bytes);
    } else { // > 9
      throw new IllegalArgumentException("shall not reach here");
    }
  }

  /**
   * Writes a signed or unsigned 8-bit integer value in CBOR format.
   *
   * @param value the value to write, values in the range [-256..255] are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeInt8(int value) throws IOException {
    // extends the sign over all bits...
    int sign = value >> 31;
    // in case value is negative, this bit should be set...
    int mt = (sign & NEG_INT_MASK);
    // complement negative value...
    writeUInt8(mt, (sign ^ value) & 0xff);
  }

  /**
   * Writes the start of an indefinite-length map.
   * <p>
   * After calling this method, one is expected to write any number of map entries, as separate key and value.
   * Keys and values can both be of any type. No length checks are performed.<p>
   * After all map entries are written, one should write a single break value to end the map,
   * see {@link #writeBreak()}.
   * </p>
   *
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeMapStart() throws IOException {
    writeSimpleType(TYPE_MAP, BREAK);
  }

  /**
   * Writes the start of a finite-length map.
   * <p>
   * After calling this method, one is expected to write any number of map entries, as separate key and value.
   * Keys and values can both be of any type. No length checks are performed.
   * </p>
   *
   * @param length the number of map entries to write, should &gt;= 0.
   * @throws IllegalArgumentException in case the given length was negative;
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeMapStart(int length) throws IOException {
    Args.notNegative(length, "lengh of map");
    writeType(TYPE_MAP, length);
  }

  /**
   * Writes a <code>null</code> value in canonical CBOR format.
   *
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeNull() throws IOException {
    writeSimpleType(TYPE_FLOAT_SIMPLE, NULL);
  }

  /**
   * Writes a simple value, i.e., an "atom" or "constant" value in canonical CBOR format.
   *
   * @param simpleValue the (unsigned byte) value to write, values from 32 to 255 are supported (though not enforced).
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeSimpleValue(byte simpleValue) throws IOException {
    // convert to unsigned value...
    int value = (simpleValue & 0xff);
    writeType(TYPE_FLOAT_SIMPLE, value);
  }

  /**
   * Writes a signed or unsigned small (&lt;= 23) integer value in CBOR format.
   *
   * @param value the value to write, values in the range [-24..23] are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeSmallInt(int value) throws IOException {
    // extends the sign over all bits...
    int sign = value >> 31;
    // in case value is negative, this bit should be set...
    int mt = (sign & NEG_INT_MASK);
    // complement negative value...
    value = Math.min(0x17, (sign ^ value));

    write(mt | value);
  }

  /**
   * Writes a semantic tag in canonical CBOR format.
   *
   * @param tag the tag to write, should &gt;= 0.
   * @throws IllegalArgumentException in case the given tag was negative;
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeTag(long tag) throws IOException {
    Args.notNegative(tag, "tag");
    writeType(TYPE_TAG, tag);
  }

  /**
   * Writes an UTF-8 string in canonical CBOR-format.
   * <p>
   * Note that this method is <em>platform</em> specific, as the given string value will be encoded in a byte array
   * using the <em>platform</em> encoding! This means that the encoding must be standardized and known.
   * </p>
   *
   * @param value the UTF-8 string to write, can be <code>null</code> in case a <code>null</code> will be written.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeTextString(String value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeString(TYPE_TEXT_STRING, value.getBytes(StandardCharsets.UTF_8));
    }
  }

  /**
   * Writes the start of an indefinite-length UTF-8 string.
   * <p>
   * After calling this method, one is expected to write the given number of string parts. No length checks are performed.<p>
   * After all string parts are written, one should write a single break value to end the string, see {@link #writeBreak()}.
   * </p>
   *
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeTextStringStart() throws IOException {
    writeSimpleType(TYPE_TEXT_STRING, BREAK);
  }

  /**
   * Writes an "undefined" value in canonical CBOR format.
   *
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public void writeUndefined() throws IOException {
    writeSimpleType(TYPE_FLOAT_SIMPLE, UNDEFINED);
  }

  /**
   * Encodes and writes the major type and value as a simple type.
   *
   * @param majorType the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from [0..31] are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeSimpleType(int majorType, int value) throws IOException {
    write((majorType << 5) | (value & 0x1f));
  }

  /**
   * Writes a byte string in canonical CBOR-format.
   *
   * @param majorType the major type of the string, should be either 0x40 or 0x60;
   * @param bytes the byte string to write, can be <code>null</code> in which case a null is written.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeString(int majorType, byte[] bytes) throws IOException {
    writeString(majorType, bytes, 0, bytes.length);
  }

  protected void writeString(int majorType, byte[] bytes, int off, int len) throws IOException {
    writeType(majorType, len);
    write(bytes, off, len);
  }

  /**
   * Encodes and writes the major type indicator with a given payload (length).
   *
   * @param majorType the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeType(int majorType, long value) throws IOException {
    writeUInt((majorType << 5), value);
  }

  /**
   * Encodes and writes an unsigned integer value, that is, tries to encode it in a little bytes as possible.
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeUInt(int mt, long value) throws IOException {
    if (value < 0x18L) {
      write((int) (mt | value));
    } else if (value < 0x100L) {
      writeUInt8(mt, (int) value);
    } else if (value < 0x10000L) {
      writeUInt16(mt, (int) value);
    } else if (value < 0x100000000L) {
      writeUInt32(mt, (int) value);
    } else {
      writeUInt64(mt, value);
    }
  }

  /**
   * Encodes and writes an unsigned 16-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeUInt16(int mt, int value) throws IOException {
    write(mt | TWO_BYTES);
    write(value >> 8);
    write(value & 0xFF);
  }

  /**
   * Encodes and writes an unsigned 32-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeUInt32(int mt, int value) throws IOException {
    write(mt | FOUR_BYTES);
    write(value >> 24);
    write(value >> 16);
    write(value >> 8);
    write(value & 0xFF);
  }

  /**
   * Encodes and writes an unsigned 64-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeUInt64(int mt, long value) throws IOException {
    write(mt | EIGHT_BYTES);
    write((int) (value >> 56));
    write((int) (value >> 48));
    write((int) (value >> 40));
    write((int) (value >> 32));
    write((int) (value >> 24));
    write((int) (value >> 16));
    write((int) (value >> 8));
    write((int) (value & 0xFF));
  }

  /**
   * Encodes and writes an unsigned 8-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected void writeUInt8(int mt, int value) throws IOException {
    write(mt | ONE_BYTE);
    write(value & 0xFF);
  }

  // added by PQ Trust
  public void writeTextStrings(String... value) throws IOException {
    if (value == null) {
      writeNull();
      return;
    }

    writeArrayStart(value.length);
    for (String v : value) {
      writeTextString(v);
    }
  }

  public void writeByteStrings(byte[]... value) throws IOException {
    if (value == null) {
      writeNull();
      return;
    }

    writeArrayStart(value.length);
    for (byte[] v : value) {
      writeByteString(v);
    }
  }

  public void writeInstant(Instant value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeTag(TAG_EPOCH_DATE_TIME);
      writeInt(value.getEpochSecond());
    }
  }

  public void writeBigInt(BigInteger value) throws IOException {
    if (value == null) {
      writeNull();
      return;
    }

    boolean neg = value.signum() == -1;
    long tag = neg ? TAG_NEGATIVE_BIGINT : TAG_POSITIVE_BIGINT;
    byte[] bytes;
    if (neg) {
      BigInteger v = value.negate().subtract(BigInteger.ONE);
      bytes = v.toByteArray();
    } else {
      bytes = value.toByteArray();
    }
    writeTag(tag);
    if (bytes.length > 1 && bytes[0] == 0) { // remove leading zeros
      writeByteString(bytes, 1, bytes.length - 1);
    } else {
      writeByteString(bytes);
    }
  }

  public void writeBigInts(BigInteger... value) throws IOException {
    if (value == null) {
      writeNull();
      return;
    }

    writeArrayStart(value.length);
    for (BigInteger bn : value) {
      writeBigInt(bn);
    }
  }

  public void writeUnwrappedBiguint(BigInteger value)
      throws IOException, EncodeException {
    if (value == null) {
      writeNull();
      return;
    }

    if (value.signum() == -1) {
      throw new EncodeException("negative value is not allowed");
    }
    byte[] bytes = value.toByteArray();
    if (bytes.length > 1 && bytes[0] == 0) { // remove leading zeros
      writeByteString(bytes, 1, bytes.length - 1);
    } else {
      writeByteString(bytes);
    }
  }

  public void writeUnwrappedTime(Instant value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeInt(value.getEpochSecond());
    }
  }

  public void writeIntObj(Long value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeInt(value);
    }
  }

  public void writeIntObj(Integer value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeInt(value);
    }
  }

  public void writeLongs(long... value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeArrayStart(value.length);
      for (long v : value) {
        writeInt(v);
      }
    }
  }

  public void writeLongs(List<Long> value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeArrayStart(value.size());
      for (Long v : value) {
        writeIntObj(v);
      }
    }
  }

  public void writeInts(int... value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeArrayStart(value.length);
      for (int v : value) {
        writeInt(v);
      }
    }
  }

  public void writeInts(List<Integer> value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeArrayStart(value.size());
      for (Integer v : value) {
        writeIntObj(v);
      }
    }
  }

  public void writeBooleanObj(Boolean value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeBoolean(value);
    }
  }

  public void writeEnumObj(Enum<?> value) throws IOException {
    if (value == null) {
      writeNull();
    } else {
      writeTextString(value.name());
    }
  }

  public void writeObject(CborEncodable object) throws IOException, EncodeException {
    if (object == null) {
      writeNull();
    } else {
      object.encode(this);
    }
  }

  public void writeObjects(CborEncodable... objects) throws IOException, EncodeException {
    if (objects == null) {
      writeNull();
    } else {
      writeArrayStart(objects.length);
      for (CborEncodable v : objects) {
        writeObject(v);
      }
    }
  }

  public void writeAnyObject(Object obj) throws IOException, EncodeException {
    if (obj == null) {
      writeNull();
    } else if (obj instanceof CborEncodable) {
      writeObject((CborEncodable) obj);
    } else if (obj instanceof Byte) {
      writeInt((byte) obj);
    } else if (obj instanceof Short) {
      writeInt((short) obj);
    } else if (obj instanceof Integer) {
      writeInt((int) obj);
    } else if (obj instanceof Long) {
      writeInt((long) obj);
    } else if (obj instanceof String) {
      writeTextString((String) obj);
    } else if (obj instanceof Boolean) {
      writeBoolean((boolean) obj);
    } else if (obj instanceof byte[]) {
      writeByteString((byte[]) obj);
    } else if (obj instanceof Object[]) {
      // check whether the if-condition works.
      Object[] array = (Object[]) obj;
      writeArrayStart(array.length);
      for (Object m : array) {
        writeAnyObject(m);
      }
    } else if (obj instanceof Collection) {
      Collection<?> array = (Collection<?>) obj;
      writeArrayStart(array.size());
      for (Object m : array) {
        writeAnyObject(m);
      }
    } else if (obj instanceof Map) {
      Map<?, ?> map = (Map<?, ?>) obj;
      writeMapStart(map.size());
      for (Object key : map.keySet()) {
        writeAnyObject(key);
        writeAnyObject(map.get(key));
      }
    } else {
      throw new EncodeException("unknown object class " + obj.getClass().getName());
    }
  }

}
