// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package org.xipki.util.codec.cbor;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.xipki.util.codec.cbor.CborConstants.TYPE_TEXT_STRING;

/**
 * Provides a decoder capable of handling CBOR encoded data from a
 * {@link InputStream}.
 */
public class ByteArrayCborDecoder extends CborDecoder {

  private final byte[] m_is;

  private final int startPosition;

  private final int maxPosition; // exclusive

  private int position;

  /**
   * Creates a new {@link ByteArrayCborDecoder} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from,
   *          cannot be <code>null</code>.
   */
  public ByteArrayCborDecoder(InputStream is) throws IOException {
    this(Args.notNull(is, "is").readAllBytes());
  }

  /**
   * Creates a new {@link ByteArrayCborDecoder} instance.
   * @param bytes the encoded cbor message.
   */
  public ByteArrayCborDecoder(byte[] bytes) {
    m_is = Args.notNull(bytes, "bytes");
    position = 0;
    startPosition = 0;
    maxPosition = bytes.length;
  }

  /**
   * Creates a new {@link ByteArrayCborDecoder} instance.
   * @param bytes the encoded cbor message.
   * @param offset offset of bytes for the cbor message.
   * @param len length of the bytes for the cbor message.
   */
  public ByteArrayCborDecoder(byte[] bytes, int offset, int len)
      throws IOException {
    Args.notNull(bytes, "bytes");
    Args.min(offset, "offset", 0);
    if (offset + len > bytes.length) {
      throw new IOException("bytes too short");
    }
    this.m_is = bytes;
    this.position = offset;
    this.startPosition = offset;
    this.maxPosition = offset + len;
  }

  @Override
  public int streamOffset() {
    return position;
  }

  public byte[] remainingBytes() {
    return Arrays.copyOfRange(m_is, position, maxPosition);
  }

  public void writeConsumedBytes(OutputStream os) throws IOException {
    os.write(m_is, startPosition, position - startPosition);
  }

  private static void fail(String msg, Object... args) throws CodecException {
    throw new CodecException(String.format(msg, args));
  }

  @Override
  public CborType peekType() throws CodecException {
    if (position >= maxPosition) {
      throw new CodecException("bytes too short");
    }

    return CborType.valueOf(0xFF & m_is[position]);
  }

  /**
   * Peeks in the input stream for the upcoming type.
   *
   * @return the upcoming type in the stream, or <code>null</code> in case of
   *         an end-of-stream.
   * @throws CodecException in case of I/O problems reading the CBOR-type from
   *         the underlying input stream.
   */
  @Override
  public CborType[] peekTypes(int num) throws CodecException {
    if (position + num - 1 >= maxPosition) {
      throw new CodecException("bytes too short");
    }

    CborType[] ret = new CborType[num];
    for (int i = 0; i < num; i++) {
      ret[i] = CborType.valueOf(0xFF & m_is[position + i]);
    }

    return ret;
  }

  /**
   * read one byte
   * @return the read byte.
   * @throws CodecException in case of I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  @Override
  public int read1Byte() throws CodecException {
    if (position >= maxPosition) {
      throw new CodecException("bytes too short");
    }
    return m_is[position++];
  }

  boolean hasMoreBytes() {
    return position < maxPosition;
  }

  /**
   * Reads a UTF-8 encoded string value in CBOR format.
   *
   * @return the read UTF-8 encoded string, or <code>null</code>.
   * @throws CodecException in case of CBOR decoding problem or I/O problems
   *         reading the CBOR-encoded value from the underlying input stream.
   */
  @Override
  public String readTextString() throws CodecException {
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
      throw new CodecException("bytes too short");
    }

    String str = new String(m_is, position, (int) len, StandardCharsets.UTF_8);
    position += (int) len;
    return str;
  }

  /**
   * Reads an unsigned 16-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *         {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  @Override
  protected int readUInt16() throws CodecException {
    if (position + 2 > maxPosition) {
      throw new CodecException("bytes too short");
    }

    return (m_is[position++] & 0xFF) << 8
        | (m_is[position++] & 0xFF);
  }

  /**
   * Reads an unsigned 32-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *         {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  @Override
  protected long readUInt32() throws CodecException {
    if (position + 4 > maxPosition) {
      throw new CodecException("bytes too short");
    }

    return ((m_is[position++] & 0xFFL) << 24
        | (m_is[position++] & 0xFFL) << 16
        | (m_is[position++] & 0xFFL) << 8
        | (m_is[position++] & 0xFFL)) & 0xffffffffL;
  }

  /**
   * Reads an unsigned 64-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *        {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  @Override
  protected long readUInt64() throws CodecException {
    if (position + 8 > maxPosition) {
      throw new CodecException("bytes too short");
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
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *         {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  @Override
  protected int readUInt8() throws CodecException {
    if (position >= maxPosition) {
      throw new CodecException("bytes too short");
    }

    return m_is[position++] & 0xff;
  }

  @Override
  protected byte[] readExactly(int len) throws CodecException {
    if (position + len > maxPosition) {
      throw new CodecException("bytes too short");
    }
    byte[] ret = Arrays.copyOfRange(m_is, position, position + len);
    position += len;
    return ret;
  }

}
