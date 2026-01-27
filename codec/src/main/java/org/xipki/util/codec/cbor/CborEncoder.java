// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 *
 * Licensed under Apache License v2.0.
 */
package org.xipki.util.codec.cbor;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.xipki.util.codec.cbor.CborConstants.*;

/**
 * Provides an encoder capable of encoding data into CBOR format to a given {@link OutputStream}.
 */
public abstract class CborEncoder {

  private static final int NEG_INT_MASK = TYPE_NEGATIVE_INTEGER << 5;
  private static final BigInteger _2power64 = new BigInteger("10000000000000000", 16);

  protected abstract void write(byte b) throws CodecException;

  protected abstract void write(int b) throws CodecException;

  protected void write(byte[] bytes) throws CodecException {
    write(bytes, 0, bytes.length);
  }

  protected abstract void write(byte[] bytes, int off, int len)
      throws CodecException;

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
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeArrayStart() throws CodecException {
    return writeSimpleType(TYPE_ARRAY, BREAK);
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
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeArrayStart(int length) throws CodecException {
    Args.notNegative(length, "array-length");
    return writeType(TYPE_ARRAY, length);
  }

  /**
   * Writes a boolean value in canonical CBOR format.
   *
   * @param value the boolean to write.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeBoolean(boolean value) throws CodecException {
    return writeSimpleType(TYPE_FLOAT_SIMPLE, value ? TRUE : FALSE);
  }

  /**
   * Writes a "break" stop-value in canonical CBOR format.
   *
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeBreak() throws CodecException {
    return writeSimpleType(TYPE_FLOAT_SIMPLE, BREAK);
  }

  /**
   * Writes a byte string in canonical CBOR-format.
   *
   * @param bytes the byte string to write, can be <code>null</code> in which case a null is written.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeByteString(byte[] bytes) throws CodecException {
    return (bytes == null) ? writeNull() : writeString(TYPE_BYTE_STRING, bytes);
  }

  public CborEncoder writeByteString(byte[] bytes, int off, int len)
      throws CodecException {
    return writeString(TYPE_BYTE_STRING, bytes, off, len);
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
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeByteStringStart() throws CodecException {
    return writeSimpleType(TYPE_BYTE_STRING, BREAK);
  }

  /**
   * Writes a double-precision float value in canonical CBOR format.
   *
   * @param value the value to write, values from {@link Double#MIN_VALUE} to {@link Double#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeDouble(double value) throws CodecException {
    return writeUInt64(TYPE_FLOAT_SIMPLE << 5,
        Double.doubleToRawLongBits(value));
  }

  /**
   * Writes a single-precision float value in canonical CBOR format.
   *
   * @param value the value to write, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeFloat(float value) throws CodecException {
    return writeUInt32(TYPE_FLOAT_SIMPLE << 5,
        Float.floatToRawIntBits(value));
  }

  /**
   * Writes a half-precision float value in canonical CBOR format.
   *
   * @param value the value to write, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeHalfPrecisionFloat(float value)
      throws CodecException {
    return writeUInt16(TYPE_FLOAT_SIMPLE << 5,
        halfPrecisionToRawIntBits(value));
  }

  public CborEncoder writeUint(BigInteger value) throws CodecException {
    int bitLength = value.bitLength();
    if (value.signum() == -1 || bitLength > 64) {
      throw new IllegalArgumentException("value not in the range [0, 2^64 - 1]");
    }

    return (bitLength <= 63) ? writeLong(value.longValueExact())
        : writeUInt64(0, value.longValue());
  }

  /**
   * Writes a signed or unsigned integer value in canonical CBOR format, that is, tries to encode it in a little
   * bytes as possible.
   *
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeInt(int value) throws CodecException {
    writeLong(value);
    return this;
  }

  public CborEncoder writeLong(long value) throws CodecException {
    // extends the sign over all bits...
    long sign = value >> 63;
    // in case value is negative, this bit should be set...
    int mt = (int) (sign & NEG_INT_MASK);
    // complement negative value...
    value = (sign ^ value);

    return writeUInt(mt, value);
  }

  /**
   * Writes a signed or unsigned 16-bit integer value in CBOR format.
   *
   * @param value the value to write, values from [-65536..65535] are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeInt16(int value) throws CodecException {
    // extends the sign over all bits...
    int sign = value >> 31;
    // in case value is negative, this bit should be set...
    int mt = (sign & NEG_INT_MASK);
    // complement negative value...
    return writeUInt16(mt, (sign ^ value) & 0xffff);
  }

  /**
   * Writes a signed or unsigned 32-bit integer value in CBOR format.
   *
   * @param value the value to write, values in the range [-4294967296..4294967295] are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeInt32(long value) throws CodecException {
    // extends the sign over all bits...
    long sign = value >> 63;
    // in case value is negative, this bit should be set...
    int mt = (int) (sign & NEG_INT_MASK);
    // complement negative value...
    return writeUInt32(mt, (int) ((sign ^ value) & 0xffffffffL));
  }

  /**
   * Writes a signed or unsigned 64-bit integer value in CBOR format.
   *
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeInt64(long value) throws CodecException {
    // extends the sign over all bits...
    long sign = value >> 63;
    // in case value is negative, this bit should be set...
    int mt = (int) (sign & NEG_INT_MASK);
    // complement negative value...
    return writeUInt64(mt, sign ^ value);
  }

  public CborEncoder writeNegInt64(BigInteger value) throws CodecException {
    int signum = value.signum();
    if (signum != -1) {
      throw new CodecException("value not in the range [-2^64, -1]");
    }

    value = value.negate();
    if (value.compareTo(_2power64) > 0) {
      throw new CodecException("value not in the range [-2^64, -1]");
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
      throw new CodecException("shall not reach here");
    }
    return this;
  }

  /**
   * Writes a signed or unsigned 8-bit integer value in CBOR format.
   *
   * @param value the value to write, values in the range [-256..255] are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeInt8(int value) throws CodecException {
    // extends the sign over all bits...
    int sign = value >> 31;
    // in case value is negative, this bit should be set...
    int mt = (sign & NEG_INT_MASK);
    // complement negative value...
    return writeUInt8(mt, (sign ^ value) & 0xff);
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
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeMapStart() throws CodecException {
    return writeSimpleType(TYPE_MAP, BREAK);
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
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeMapStart(int length) throws CodecException {
    Args.notNegative(length, "lengh of map");
    return writeType(TYPE_MAP, length);
  }

  /**
   * Writes a <code>null</code> value in canonical CBOR format.
   *
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeNull() throws CodecException {
    return writeSimpleType(TYPE_FLOAT_SIMPLE, NULL);
  }

  /**
   * Writes a simple value, i.e., an "atom" or "constant" value in canonical CBOR format.
   *
   * @param simpleValue the (unsigned byte) value to write, values from 32 to 255 are supported (though not enforced).
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeSimpleValue(byte simpleValue) throws CodecException {
    // convert to unsigned value...
    int value = (simpleValue & 0xff);
    return writeType(TYPE_FLOAT_SIMPLE, value);
  }

  /**
   * Writes a signed or unsigned small (&lt;= 23) integer value in CBOR format.
   *
   * @param value the value to write, values in the range [-24..23] are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeSmallInt(int value) throws CodecException {
    // extends the sign over all bits...
    int sign = value >> 31;
    // in case value is negative, this bit should be set...
    int mt = (sign & NEG_INT_MASK);
    // complement negative value...
    value = Math.min(0x17, (sign ^ value));

    write(mt | value);
    return this;
  }

  /**
   * Writes a semantic tag in canonical CBOR format.
   *
   * @param tag the tag to write, should &gt;= 0.
   * @throws IllegalArgumentException in case the given tag was negative;
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  public CborEncoder writeTag(long tag) throws CodecException {
    Args.notNegative(tag, "tag");
    return writeType(TYPE_TAG, tag);
  }

  /**
   * Writes an alternative enum in canonical CBOR format.
   * See https://www.ietf.org/archive/id/draft-bormann-cbor-notable-tags-12.html#name-enumerated-alternative-data
   *
   * @param alternative the alternative enum to write, should &gt;= 0.
   * @throws IllegalArgumentException in case the given tag was negative;
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  public CborEncoder writeAlternative(int alternative) throws CodecException {
    Args.notNegative(alternative, "alternative");
    if (alternative <= 6) {
      writeTag(121 + alternative);
    } else if (alternative <= 127) {
      writeTag(1273 + alternative);
    } else {
      writeTag(101);
      writeArrayStart(2);
      writeInt(alternative - 128);
    }
    return this;
  }

  /**
   * Writes an UTF-8 string in canonical CBOR-format.
   * <p>
   * Note that this method is <em>platform</em> specific, as the given string value will be encoded in a byte array
   * using the <em>platform</em> encoding! This means that the encoding must be standardized and known.
   * </p>
   *
   * @param value the UTF-8 string to write, can be <code>null</code> in case a <code>null</code> will be written.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeTextString(String value) throws CodecException {
    return (value == null) ? writeNull()
        : writeString(TYPE_TEXT_STRING, value.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Writes the start of an indefinite-length UTF-8 string.
   * <p>
   * After calling this method, one is expected to write the given number of string parts. No length checks are performed.<p>
   * After all string parts are written, one should write a single break value to end the string, see {@link #writeBreak()}.
   * </p>
   *
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeTextStringStart() throws CodecException {
    return writeSimpleType(TYPE_TEXT_STRING, BREAK);
  }

  /**
   * Writes an "undefined" value in canonical CBOR format.
   *
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  public CborEncoder writeUndefined() throws CodecException {
    return writeSimpleType(TYPE_FLOAT_SIMPLE, UNDEFINED);
  }

  /**
   * Encodes and writes the major type and value as a simple type.
   *
   * @param majorType the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from [0..31] are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeSimpleType(int majorType, int value)
      throws CodecException {
    write((majorType << 5) | (value & 0x1f));
    return this;
  }

  /**
   * Writes a byte string in canonical CBOR-format.
   *
   * @param majorType the major type of the string, should be either 0x40 or 0x60;
   * @param bytes the byte string to write, can be <code>null</code> in which case a null is written.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeString(int majorType, byte[] bytes)
      throws CodecException {
    return writeString(majorType, bytes, 0, bytes.length);
  }

  protected CborEncoder writeString(int majorType, byte[] bytes, int off, int len)
      throws CodecException {
    writeType(majorType, len);
    write(bytes, off, len);
    return this;
  }

  /**
   * Encodes and writes the major type indicator with a given payload (length).
   *
   * @param majorType the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeType(int majorType, long value)
      throws CodecException {
    return writeUInt((majorType << 5), value);
  }

  /**
   * Encodes and writes an unsigned integer value, that is, tries to encode it in a little bytes as possible.
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeUInt(int mt, long value) throws CodecException {
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

    return this;
  }

  /**
   * Encodes and writes an unsigned 16-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeUInt16(int mt, int value) throws CodecException {
    write(mt | TWO_BYTES);
    write(value >> 8);
    write(value & 0xFF);
    return this;
  }

  /**
   * Encodes and writes an unsigned 32-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeUInt32(int mt, int value) throws CodecException {
    write(mt | FOUR_BYTES);
    write(value >> 24);
    write(value >> 16);
    write(value >> 8);
    write(value & 0xFF);
    return this;
  }

  /**
   * Encodes and writes an unsigned 64-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeUInt64(int mt, long value) throws CodecException {
    write(mt | EIGHT_BYTES);
    write((int) (value >> 56));
    write((int) (value >> 48));
    write((int) (value >> 40));
    write((int) (value >> 32));
    write((int) (value >> 24));
    write((int) (value >> 16));
    write((int) (value >> 8));
    write((int) (value & 0xFF));
    return this;
  }

  /**
   * Encodes and writes an unsigned 8-bit integer value
   *
   * @param mt the major type of the value to write, denotes what semantics the written value has;
   * @param value the value to write, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected CborEncoder writeUInt8(int mt, int value) throws CodecException {
    write(mt | ONE_BYTE);
    write(value & 0xFF);
    return this;
  }

  // added by xipki
  public CborEncoder writeTextStrings(String... value) throws CodecException {
    if (value == null) {
      return writeNull();
    }

    writeArrayStart(value.length);
    for (String v : value) {
      writeTextString(v);
    }
    return this;
  }

  public CborEncoder writeByteStrings(byte[]... value) throws CodecException {
    if (value == null) {
      return writeNull();
    }

    writeArrayStart(value.length);
    for (byte[] v : value) {
      writeByteString(v);
    }
    return this;
  }

  public CborEncoder writeInstant(Instant value) throws CodecException {
    return (value == null) ? writeNull()
        : writeTag(TAG_EPOCH_DATE_TIME).writeLong(value.getEpochSecond());
  }

  public CborEncoder writeBigInt(BigInteger value) throws CodecException {
    if (value == null) {
      return writeNull();
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
      return writeByteString(bytes, 1, bytes.length - 1);
    } else {
      return writeByteString(bytes);
    }
  }

  public CborEncoder writeBigInts(BigInteger... value) throws CodecException {
    if (value == null) {
      return writeNull();
    }

    writeArrayStart(value.length);
    for (BigInteger bn : value) {
      writeBigInt(bn);
    }
    return this;
  }

  public CborEncoder writeUnwrappedBiguint(BigInteger value)
      throws CodecException {
    if (value == null) {
      return writeNull();
    }

    if (value.signum() == -1) {
      throw new CodecException("negative value is not allowed");
    }
    byte[] bytes = value.toByteArray();
    if (bytes.length > 1 && bytes[0] == 0) { // remove leading zeros
      return writeByteString(bytes, 1, bytes.length - 1);
    } else {
      return writeByteString(bytes);
    }
  }

  public CborEncoder writeUnwrappedTime(Instant value) throws CodecException {
    return (value == null) ? writeNull() : writeLong(value.getEpochSecond());
  }

  public CborEncoder writeLongObj(Long value) throws CodecException {
    return (value == null) ? writeNull() : writeLong(value);
  }

  public CborEncoder writeIntObj(Integer value) throws CodecException {
    return (value == null) ? writeNull() : writeInt(value);
  }

  public CborEncoder writeLongs(long... value) throws CodecException {
    if (value == null) {
      return writeNull();
    }

    writeArrayStart(value.length);
    for (long v : value) {
      writeLong(v);
    }
    return this;
  }

  public CborEncoder writeLongs(List<Long> value) throws CodecException {
    if (value == null) {
      return writeNull();
    }

    writeArrayStart(value.size());
    for (Long v : value) {
      writeLongObj(v);
    }
    return this;
  }

  public CborEncoder writeInts(int... value) throws CodecException {
    if (value == null) {
      return writeNull();
    }

    writeArrayStart(value.length);
    for (int v : value) {
      writeInt(v);
    }

    return this;
  }

  public CborEncoder writeInts(List<Integer> value) throws CodecException {
    if (value == null) {
      return writeNull();
    }

    writeArrayStart(value.size());
    for (Integer v : value) {
      writeIntObj(v);
    }
    return this;
  }

  public CborEncoder writeBooleanObj(Boolean value) throws CodecException {
    return (value == null) ? writeNull() : writeBoolean(value);
  }

  public CborEncoder writeEnumObj(Enum<?> value) throws CodecException {
    return (value == null) ? writeNull() : writeTextString(value.name());
  }

  public CborEncoder writeObject(CborEncodable object)
      throws CodecException {
    if (object == null) {
      return writeNull();
    } else {
      object.encode(this);
      return this;
    }
  }

  public CborEncoder writeObjects(CborEncodable... objects)
      throws CodecException {
    if (objects == null) {
      return writeNull();
    }

    writeArrayStart(objects.length);
    for (CborEncodable v : objects) {
      writeObject(v);
    }
    return this;
  }

  public CborEncoder writeAnyObject(Object obj) throws CodecException {
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
      writeLong((long) obj);
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
      throw new CodecException("unknown object class " + obj.getClass().getName());
    }

    return this;
  }

}
