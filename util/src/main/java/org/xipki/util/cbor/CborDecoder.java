// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package org.xipki.util.cbor;

import org.xipki.util.Args;
import org.xipki.util.DateUtil;
import org.xipki.util.exception.DecodeException;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.xipki.util.cbor.CborConstants.*;

/**
 * Provides a decoder capable of handling CBOR encoded data from a {@link InputStream}.
 */
public class CborDecoder implements AutoCloseable {

  private static final BigInteger U = new BigInteger("10000000000000000", 16);

  private final byte[] m_is;

  private final int maxPosition; // exclusive

  private int position;

  /**
   * Creates a new {@link CborDecoder} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from, cannot be <code>null</code>.
   */
  public CborDecoder(InputStream is) throws IOException {
    Args.notNull(is, "is");
    m_is = is.readAllBytes();
    position = 0;
    maxPosition = m_is.length;
  }

  /**
   * Creates a new {@link CborDecoder} instance.
   * @param bytes the encoded cbor message.
   */
  public CborDecoder(byte[] bytes) {
    this.m_is = Args.notNull(bytes, "bytes");
    this.position = 0;
    this.maxPosition = bytes.length;
  }

  /**
   * Creates a new {@link CborDecoder} instance.
   * @param bytes the encoded cbor message.
   * @param offset offset of bytes for the cbor message.
   * @param len length of the bytes for the cbor message.
   */
  public CborDecoder(byte[] bytes, int offset, int len) throws IOException {
    Args.notNull(bytes, "bytes");
    Args.min(offset, "offset", 0);
    if (offset + len > bytes.length) {
      throw new IOException("bytes too short");
    }
    this.m_is = bytes;
    this.position = offset;
    this.maxPosition = offset + len;
  }

  public int getStreamOffset() {
    return position;
  }

  private static void fail(String msg, Object... args) throws DecodeException {
    throw new DecodeException(String.format(msg, args));
  }

  static String lengthToString(int len) {
    return (len < 0) ? "no payload"
      : (len == ONE_BYTE)  ? "one byte"
      : (len == TWO_BYTES)   ? "two bytes"
      : (len == FOUR_BYTES)  ? "four bytes"
      : (len == EIGHT_BYTES) ? "eight bytes"
      : "(unknown)";
  }

  /**
   * Peeks in the input stream for the upcoming type.
   *
   * @return the upcoming type in the stream, or <code>null</code> in case of an end-of-stream.
   * @throws DecodeException in case of I/O problems reading the CBOR-type from the underlying input stream.
   */
  public CborType peekType() throws DecodeException {
    if (position >= maxPosition) {
      throw new DecodeException("bytes too short");
    }

    return CborType.valueOf(0xFF & m_is[position]);
  }

  /**
   * Peeks in the input stream for the upcoming types.
   *
   * @return the upcoming types in the stream, or <code>null</code> in case of an end-of-stream.
   * @throws DecodeException in case of I/O problems reading the CBOR-type from the underlying input stream.
   */
  public CborType[] peek2Types() throws DecodeException {
    if (position >= maxPosition) {
      throw new DecodeException("bytes too short");
    }

    if (position + 1 >= maxPosition) {
      throw new IndexOutOfBoundsException(position + 1);
    }

    return new CborType[] {
        CborType.valueOf(0xFF & m_is[position]),
        CborType.valueOf(0xFF & m_is[position + 1])};
  }

  /**
   * read one bye
   * @return the read byte.
   * @throws DecodeException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  public int read1Byte() throws DecodeException {
    if (position >= maxPosition) {
      throw new DecodeException("bytes too short");
    }
    return m_is[position++];
  }

  boolean hasMoreBytes() {
    return position < maxPosition;
  }

  /**
   * Prolog to reading an array value in CBOR format.
   *
   * @return the number of elements in the array to read, or -1 in case of infinite-length arrays.
   * @throws DecodeException in case of CBOR decoding error or I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  public int readArrayLength() throws DecodeException {
    long len = readMajorTypeWithSize(TYPE_ARRAY);
    if (len < -1 || len > Integer.MAX_VALUE) {
      // -1: break / infinite length
      throw new DecodeException("array length not in range [0, " + Integer.MAX_VALUE + "]");
    }
    return (int) len;
  }

  /**
   * Reads a boolean value in CBOR format.
   *
   * @return the read boolean.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public boolean readBoolean() throws DecodeException {
    int b = readMajorType(TYPE_FLOAT_SIMPLE);
    if (b != FALSE && b != TRUE) {
      fail("Unexpected boolean value: %d!", b);
    }
    return b == TRUE;
  }

  /**
   * Reads a "break"/stop value in CBOR format.
   *
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public void readBreak() throws DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, BREAK);
  }

  /**
   * Reads a byte string value in CBOR format.
   *
   * @return the read byte string, or <code>null</code>.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public byte[] readByteString() throws DecodeException {
    if (skipNull()) {
      return null;
    }

    long len = readMajorTypeWithSize(TYPE_BYTE_STRING);
    if (len < 0) {
      fail("Infinite-length byte strings not supported!");
    }
    if (len > Integer.MAX_VALUE) {
      fail("String length too long!");
    }
    return readExactly((int) len);
  }

  /**
   * Prolog to reading a byte string value in CBOR format.
   *
   * @return the number of bytes in the string to read, or -1 in case of infinite-length strings.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public long readByteStringLength() throws DecodeException {
    return readMajorTypeWithSize(TYPE_BYTE_STRING);
  }

  /**
   * Reads a double-precision float value in CBOR format.
   *
   * @return the read double value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws DecodeException in case of CBOR decoding problem I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  public double readDouble() throws DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, DOUBLE_PRECISION_FLOAT);

    return Double.longBitsToDouble(readUInt64());
  }

  /**
   * Reads a single-precision float value in CBOR format.
   *
   * @return the read float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  public float readFloat() throws DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, SINGLE_PRECISION_FLOAT);

    return Float.intBitsToFloat((int) readUInt32());
  }

  /**
   * Reads a half-precision float value in CBOR format.
   *
   * @return the read half-precision float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE}
   *     are supported.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  public double readHalfPrecisionFloat() throws DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, HALF_PRECISION_FLOAT);

    int half = readUInt16();
    int exp = (half >> 10) & 0x1f;
    int mant = half & 0x3ff;

    double val;
    if (exp == 0) {
      val = mant * Math.pow(2, -24);
    } else if (exp != 31) {
      val = (mant + 1024) * Math.pow(2, exp - 25);
    } else if (mant != 0) {
      val = Double.NaN;
    } else {
      val = Double.POSITIVE_INFINITY;
    }

    return ((half & 0x8000) == 0) ? val : -val;
  }

  /**
   * Reads an unsigned integer value in CBOR format in the range [0, 2^64 - 1].
   *
   * @return the read integer value.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public BigInteger readUint() throws DecodeException {
    int ib = read1Byte();

    // in case of negative integers does a ones complement
    long value = readUInt(ib & 0x1f, false /* breakAllowed */, true);

    if (value < 0) {
      return U.add(BigInteger.valueOf(value));
    } else {
      return BigInteger.valueOf(value);
    }
  }

  /**
   * Reads a signed or unsigned integer value in CBOR format.
   *
   * @return the read integer value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  public long readLong() throws DecodeException {
    int ib = read1Byte();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUInt(ib & 0x1f, false /* breakAllowed */);
  }

  public long[] readLongs() throws DecodeException {
    Integer arrayLen = readNullOrArrayLength();
    if (arrayLen == null) {
      return null;
    }

    long[] ret = new long[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      ret[i] = readLong();
    }

    return ret;
  }

  public List<Long> readLongList() throws DecodeException {
    Integer arrayLen = readNullOrArrayLength();
    if (arrayLen == null) {
      return null;
    }

    List<Long> ret = new ArrayList<>(arrayLen);
    for (int i = 0; i < arrayLen; i++) {
      ret.add(readLong());
    }

    return ret;
  }

  /**
   * Reads a signed or unsigned 16-bit integer value in CBOR format.
   * <p>
   * read the small integer value, values from [-65536..65535] are supported.
   * @return the read 16-bit integer.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying output stream.
   */
  public int readInt16() throws DecodeException {
    int ib = read1Byte();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(TWO_BYTES, ib & 0x1f));
  }

  /**
   * Reads a signed or unsigned 32-bit integer value in CBOR format.
   * <p>
   * read the small integer value, values in the range [-4294967296..4294967295] are supported.
   * @return the read 32-bit integer.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying output stream.
   */
  public long readInt32() throws DecodeException {
    int ib = read1Byte();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(FOUR_BYTES, ib & 0x1f);
  }

  /**
   * Reads a signed or unsigned 64-bit integer value in CBOR format.
   * <p>
   * read the small integer value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE}
   * are supported.
   * @return the read 64-bit integer (long).
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying output stream.
   */
  public long readInt64() throws DecodeException {
    int ib = read1Byte();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(EIGHT_BYTES, ib & 0x1f);
  }

  /**
   * Reads a signed or unsigned 8-bit integer value in CBOR format.
   * <p>
   * read the small integer value, values in the range [-256..255] are supported.
   * @return the read 8-bit integer.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying output stream.
   */
  public int readInt8() throws DecodeException {
    int ib = read1Byte();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(ONE_BYTE, ib & 0x1f));
  }

  /**
   * Prolog to reading a map of key-value pairs in CBOR format.
   *
   * @return the number of entries in the map, &gt;= 0.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems
   *         reading the CBOR-encoded value from the underlying input stream.
   */
  public int readMapLength() throws DecodeException {
    long len = readMajorTypeWithSize(TYPE_MAP);
    if (len < -1 || len > Integer.MAX_VALUE) {
      // -1: break / infinite length
      throw new DecodeException("map length not in range [0, " + Integer.MAX_VALUE + "]");
    }
    return (int) len;

  }

  /**
   * Reads a <code>null</code>-value in CBOR format.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public void readNull() throws DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, NULL);
  }

  /**
   * Reads a single byte value in CBOR format.
   *
   * @return the read byte value.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  public byte readSimpleValue() throws DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, ONE_BYTE);
    return (byte) readUInt8();
  }

  /**
   * Reads a signed or unsigned small (&lt;= 23) integer value in CBOR format.
   * <p>
   * read the small integer value, values in the range [-24..23] are supported.
   * @return the read small int.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying output stream.
   */
  public int readSmallInt() throws DecodeException {
    int ib = read1Byte();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(-1, ib & 0x1f));
  }

  /**
   * Reads a semantic tag value in CBOR format.
   *
   * @return the read tag value.
   * @throws DecodeException in case CBOR decoding problem or of I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public long readTag() throws DecodeException {
    return readUInt(readMajorType(TYPE_TAG), false /* breakAllowed */);
  }

  /**
   * Reads a semantic tag value in CBOR format.
   *
   * @return the read tag value.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public void readTag(long expectedTag) throws DecodeException {
    long tag = readTag();
    if (tag != expectedTag) {
      fail("Unexpected tag: %s, expected tag %s!", tag, expectedTag);
    }
  }

  /**
   * Reads a UTF-8 encoded string value in CBOR format.
   *
   * @return the read UTF-8 encoded string, or <code>null</code>.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading
   *         the CBOR-encoded value from the underlying input stream.
   */
  public String readTextString() throws DecodeException {
    if (skipNull()) {
      return null;
    }

    long len = readMajorTypeWithSize(TYPE_TEXT_STRING);
    if (len < 0) {
      fail("Infinite-length text strings not supported!");
    }
    if (len > Integer.MAX_VALUE) {
      fail("String length too long!");
    }

    if (position + len > maxPosition) {
      throw new DecodeException("bytes too short");
    }

    String str = new String(m_is, position, (int) len, StandardCharsets.UTF_8);
    position += (int) len;
    return str;
  }

  /**
   * Prolog to reading a UTF-8 encoded string value in CBOR format.
   *
   * @return the length of the string to read, or -1 in case of infinite-length strings.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public long readTextStringLength() throws DecodeException {
    return readMajorTypeWithSize(TYPE_TEXT_STRING);
  }

  /**
   * Reads an undefined value in CBOR format.
   *
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  public void readUndefined() throws DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, UNDEFINED);
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether
   * it matches the given expectation.
   *
   * @param ib the expected major type, cannot be <code>null</code> (unchecked).
   * @return either -1 if the major type was a signed integer, or 0 otherwise.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  protected long expectIntegerType(int ib) throws DecodeException {
    int majorType = ((ib & 0xFF) >>> 5);
    if ((majorType != TYPE_UNSIGNED_INTEGER)
      && (majorType != TYPE_NEGATIVE_INTEGER)) {
      fail("Unexpected type: %s, expected type %s or %s!",
        CborType.getName(majorType),
        CborType.getName(TYPE_UNSIGNED_INTEGER),
        CborType.getName(TYPE_NEGATIVE_INTEGER));
    }
    return -majorType;
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
   * @return the read subtype, or payload, of the read major type.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the CBOR-encoded
   *         value from the underlying input stream.
   */
  protected int readMajorType(int majorType) throws DecodeException {
    int ib = read1Byte();
    if (majorType != ((ib >>> 5) & 0x07)) {
      fail("Unexpected type: %s, expected: %s!", CborType.getName(ib), CborType.getName(majorType));
    }
    return ib & 0x1F;
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether it matches the given
   * expectations.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked);
   * @param subtype the expected subtype.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  protected void readMajorTypeExact(int majorType, int subtype) throws DecodeException {
    int st = readMajorType(majorType);
    if ((st ^ subtype) != 0) {
      fail("Unexpected subtype: %d, expected: %d!", st, subtype);
    }
  }

  /**
   * Reads the next major type from the underlying input stream, verifies whether it matches the given expectation,
   * and decodes the payload into a size.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
   * @return the number of succeeding bytes, &gt;= 0, or -1 if an infinite-length type is read.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *  CBOR-encoded value from the underlying input stream.
   */
  protected long readMajorTypeWithSize(int majorType) throws DecodeException {
    return readUInt(readMajorType(majorType), true /* breakAllowed */);
  }

  /**
   * Reads an unsigned integer with a given length-indicator.
   *
   * @param length the length indicator to use;
   * @param breakAllowed whether break is allowed.
   * @return the read unsigned integer, as long value.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         unsigned integer from the underlying input stream.
   */
  protected long readUInt(int length, boolean breakAllowed) throws DecodeException {
    return readUInt(length, breakAllowed, false);
  }

  private long readUInt(int length, boolean breakAllowed, boolean allow64Bit)
    throws DecodeException {
    long result = -1;
    if (length < ONE_BYTE) {
      result = length;
    } else if (length == ONE_BYTE) {
      result = readUInt8();
    } else if (length == TWO_BYTES) {
      result = readUInt16();
    } else if (length == FOUR_BYTES) {
      result = readUInt32();
    } else if (length == EIGHT_BYTES) {
      result = readUInt64();
      if (allow64Bit && result < 0) {
        return result;
      }
    } else if (breakAllowed && length == BREAK) {
      return -1;
    }

    if (result < 0) {
      fail("Not well-formed CBOR integer found, invalid length: %d!", result);
    }
    return result;
  }

  /**
   * Reads an unsigned 16-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws DecodeException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected int readUInt16() throws DecodeException {
    if (position + 2 > maxPosition) {
      throw new DecodeException("bytes too short");
    }

    return (m_is[position++] & 0xFF) << 8
        | (m_is[position++] & 0xFF);
  }

  /**
   * Reads an unsigned 32-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws DecodeException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected long readUInt32() throws DecodeException {
    if (position + 4 > maxPosition) {
      throw new DecodeException("bytes too short");
    }

    return ((m_is[position++] & 0xFFL) << 24
        | (m_is[position++] & 0xFFL) << 16
        | (m_is[position++] & 0xFFL) << 8
        | (m_is[position++] & 0xFFL)) & 0xffffffffL;
  }

  /**
   * Reads an unsigned 64-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws DecodeException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected long readUInt64() throws DecodeException {
    if (position + 8 > maxPosition) {
      throw new DecodeException("bytes too short");
    }

    return (m_is[position++] & 0xFFL) << 56
        | (m_is[position++] & 0xFFL) << 48
        | (m_is[position++] & 0xFFL) << 40
        | (m_is[position++] & 0xFFL) << 32
        | (m_is[position++] & 0xFFL) << 24
        | (m_is[position++] & 0xFFL) << 16
        | (m_is[position++] & 0xFFL) << 8
        | (m_is[position++] & 0xFFL);
  }

  /**
   * Reads an unsigned 8-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws DecodeException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  protected int readUInt8() throws DecodeException {
    if (position >= maxPosition) {
      throw new DecodeException("bytes too short");
    }

    return m_is[position++] & 0xff;
  }

  /**
   * Reads an unsigned integer with a given length-indicator.
   * @param expectedLength the expected length.
   * @param length the length indicator to use;
   * @return the read unsigned integer, as long value.
   * @throws DecodeException in case of CBOR decoding problem or I/O problems reading the
   *         unsigned integer from the underlying input stream.
   */
  protected long readUIntExact(int expectedLength, int length) throws DecodeException {
    if ((expectedLength == -1 && length >= ONE_BYTE)
      || (expectedLength >= 0 && length != expectedLength)) {
      fail("Unexpected payload/length! Expected %s, but got %s.", lengthToString(expectedLength),
        lengthToString(length));
    }
    return readUInt(length, false /* breakAllowed */);
  }

  private byte[] readExactly(int len) throws DecodeException {
    if (position + len > maxPosition) {
      throw new DecodeException("bytes too short");
    }
    byte[] ret = Arrays.copyOfRange(m_is, position, position + len);
    position += len;
    return ret;
  }

  // added by PQ Trust

  /**
   * true if it is null, or false it is an array of the specified length.
   * @param expectedLen the expected length of an array.
   * @return whether it is null.
   * @throws DecodeException in case of CBOR decoding problem or if cannot decode the
   *         stream or is not an array with given length.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  public boolean readNullOrArrayLength(int expectedLen) throws DecodeException {
    Integer len = readNullOrArrayLength();
    if (len == null) {
      return true;
    } else if (len == expectedLen) {
      return false;
    }
    throw new DecodeException("stream has an array but the length != " + expectedLen +": " + len);
  }

  /**
   * read array length and assert the equality to expectedLen.
   * @param expectedLen the expected length of an array.
   * @throws DecodeException in case of CBOR decoding problem or the length is different as expected
   *         or if cannot decode the stream or is not an array with given length.
   */
  public void readArrayLength(int expectedLen) throws DecodeException {
    Integer len = readNullOrArrayLength();
    if (len == null) {
      throw new DecodeException("stream does not have an array");
    } else if (len != expectedLen) {
      throw new DecodeException("stream has an array but the length != " + expectedLen +": " + len);
    }
  }

  public Integer readNullOrArrayLength() throws DecodeException {
    CborType type = peekType();
    if (type.isNull()) {
      read1Byte();
      return null;
    } else if (type.getMajorType() == TYPE_ARRAY) {
      return readArrayLength();
    } else {
      throw new DecodeException("stream does not have an array");
    }
  }

  public Integer readNullOrMapLength() throws DecodeException {
    CborType type = peekType();
    if (isNull(type)) {
      read1Byte();
      return null;
    } else if (type.getMajorType() == TYPE_MAP) {
      return readMapLength();
    } else {
      throw new DecodeException("stream does not have an array");
    }
  }

  public Long readTagObj() throws DecodeException {
    CborType type = peekType();
    if (isNull(type)) {
      read1Byte();
      return null;
    } else if (type.getMajorType() == TYPE_TAG) {
      return readTag();
    } else {
      throw new DecodeException("stream does not have a tag");
    }
  }

  public static boolean isNull(CborType type) {
    return type.getMajorType() == TYPE_FLOAT_SIMPLE
      && type.getAdditionalInfo() == NULL;
  }

  public boolean skipBreak() throws DecodeException {
    CborType type = peekType();
    if (type.getMajorType() == TYPE_FLOAT_SIMPLE
        && type.getAdditionalInfo() == BREAK) {
      readBreak();
      return true;
    } else {
      return false;
    }
  }

  public boolean skipNull() throws DecodeException {
    if (peekType().isNull()) {
      readNull();
      return true;
    } else {
      return false;
    }
  }

  public Boolean readBooleanObj() throws DecodeException {
    CborType type = peekType();
    if (isNull(type)) {
      read1Byte();
      return null;
    } else if (type.getMajorType() == TYPE_FLOAT_SIMPLE) {
      return readBoolean();
    } else {
      throw new DecodeException("stream does not have integer");
    }
  }

  public Long readLongObj() throws DecodeException {
    CborType type = peekType();
    if (isNull(type)) {
      read1Byte();
      return null;
    } else if (type.getMajorType() == TYPE_UNSIGNED_INTEGER
      || type.getMajorType() == TYPE_NEGATIVE_INTEGER) {
      return readLong();
    } else {
      throw new DecodeException("stream does not have integer");
    }
  }

  public Integer readIntObj() throws DecodeException {
    CborType type = peekType();
    if (isNull(type)) {
      read1Byte();
      return null;
    } else if (type.getMajorType() == TYPE_UNSIGNED_INTEGER
      || type.getMajorType() == TYPE_NEGATIVE_INTEGER) {
      return readInt();
    } else {
      throw new DecodeException("stream does not have integer");
    }
  }

  public BigInteger readUnwrappedBigInt() throws DecodeException {
    if (skipNull()) {
      return null;
    }
    return new BigInteger(1, readByteString());
  }

  public BigInteger readBigInt() throws DecodeException {
    if (skipNull()) {
      return null;
    }

    long tag = readTag();
    boolean neg;
    if (tag == TAG_POSITIVE_BIGINT) {
      neg = false;
    } else if (tag == TAG_NEGATIVE_BIGINT) {
      neg = true;
    } else {
      throw new DecodeException("invalid tag " + tag);
    }

    byte[] bytes = readByteString();
    BigInteger value = new BigInteger(1, bytes);
    if (neg) {
      value = value.negate().min(BigInteger.ONE);
    }

    return value;
  }

  public Instant readInstant() throws DecodeException {
    if (skipNull()) {
      return null;
    }

    long tag = readTag();
    if (tag == TAG_STANDARD_DATE_TIME) {
      String value = readTextString();
      try {
        return DateUtil.parseRFC3339Timestamp(value);
      } catch (DateTimeParseException ex) {
        throw new DecodeException("invalid date/time " + value);
      }
    } else if (tag == TAG_EPOCH_DATE_TIME) {
      long value = readLong();
      return Instant.ofEpochSecond(value);
    } else {
      throw new DecodeException("invalid tag " + tag);
    }
  }

  public Instant readUnwrappedInstant() throws DecodeException {
    if (skipNull()) {
      return null;
    }

    long value = readLong();
    return Instant.ofEpochSecond(value);
  }

  public String[] readTextStrings() throws DecodeException {
    Integer arrayLen = readNullOrArrayLength();
    if (arrayLen == null) {
      return null;
    }

    String[] ret = new String[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      ret[i] = readTextString();
    }

    return ret;
  }

  public byte[][] readByteStrings() throws DecodeException {
    Integer arrayLen = readNullOrArrayLength();
    if (arrayLen == null) {
      return null;
    }

    byte[][] ret = new byte[arrayLen][];
    for (int i = 0; i < arrayLen; i++) {
      ret[i] = readByteString();
    }

    return ret;
  }

  public BigInteger[] readBigInts() throws DecodeException {
    Integer arrayLen = readNullOrArrayLength();
    if (arrayLen == null) {
      return null;
    }

    BigInteger[] ret = new BigInteger[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      ret[i] = readBigInt();
    }

    return ret;
  }

  public int readInt() throws DecodeException {
    long v = readLong();
    if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
      throw new DecodeException("value is out of range of int32");
    }
    return (int) v;
  }

  public int[] readInts() throws DecodeException {
    Integer arrayLen = readNullOrArrayLength();
    if (arrayLen == null) {
      return null;
    }

    int[] ret = new int[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      ret[i] = readInt();
    }

    return ret;
  }

  public List<Integer> readIntList() throws DecodeException {
    Integer arrayLen = readNullOrArrayLength();
    if (arrayLen == null) {
      return null;
    }

    List<Integer> ret = new ArrayList<>(arrayLen);
    for (int i = 0; i < arrayLen; i++) {
      ret.add(readInt());
    }

    return ret;
  }

  /**
   * break is not supported.
   */
  public Object readNext() throws DecodeException {
    return readNext(this);
  }

  public static Object readNext(CborDecoder decoder) throws DecodeException {
    CborType type = decoder.peekType();
    if (type.isNullThenRead(decoder)) {
      return null;
    } else if (type.isBooleanType()) {
      return decoder.readBoolean();
    } else if (type.isInt()) {
      return decoder.readInt();
    } else if (type.isTextString()) {
      return decoder.readTextString();
    } else if (type.isByteString()) {
      return decoder.readByteString();
    } else if (type.isArray()) {
      int arrayLen = decoder.readArrayLength();
      List<Object> array = new ArrayList<>(arrayLen);
      for (int i = 0; i< arrayLen; i++) {
        array.add(readNext(decoder));
      }
      return array;
    } else if (type.isMap()) {
      int mapLen = decoder.readMapLength();
      Map<Object, Object> map = new HashMap<>();
      for (int i = 0; i < mapLen; i++) {
        Object key = readNext(decoder);
        Object value = readNext(decoder);
        map.put(key, value);
      }
      return map;
    } else if (type.isTag()) {
      long tag = decoder.readTag();
      Object value = readNext(decoder);
      return new CborTaggedObject(tag, value);
    } else {
      throw new DecodeException("unsupported object type " + type);
    }
  }

  @Override
  public void close() {
  }

  public static Object readObject(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(encoded)){
      Object next = decoder.readNext();
      if (decoder.hasMoreBytes()) {
        throw new DecodeException("encoded contains more than 1 object.");
      } else {
        return next;
      }
    }
  }

}
