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
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;

import static org.xipki.util.codec.cbor.CborConstants.TYPE_TEXT_STRING;

/**
 * Provides a decoder capable of handling CBOR encoded data from a
 * {@link InputStream}.
 */
public class StreamCborDecoder extends CborDecoder {

  private final PushbackInputStream m_is;

  private int position;

  /**
   * Creates a new {@link StreamCborDecoder} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from,
   *          cannot be <code>null</code>.
   */
  public StreamCborDecoder(InputStream is) throws IOException {
    Args.notNull(is, "is");
    if (is instanceof PushbackInputStream) {
      this.m_is = (PushbackInputStream) is;
    } else {
      this.m_is = new PushbackInputStream(is);
    }
    this.position = 0;
  }

  private static void fail(String msg, Object... args) throws CodecException {
    throw new CodecException(String.format(msg, args));
  }

  @Override
  public int streamOffset() {
    return position;
  }

  @Override
  public CborType peekType() throws CodecException {
    int r = read1Byte();
    try {
      return CborType.valueOf(r);
    } finally {
      unread(r);
    }
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
    byte[] bytes = readExactly(num);
    CborType[] ret = new CborType[num];
    for (int i = 0; i < num; i++) {
      ret[i] = CborType.valueOf(0xFF & bytes[i]);
    }

    unread(bytes);
    return ret;
  }

  private void unread(int value) throws CodecException {
    try {
      m_is.unread(value);
    } catch (IOException e) {
      throw new CodecException(e);
    }
    position--;
  }

  /**
   * read one byte
   * @return the read byte.
   * @throws CodecException in case of I/O problems reading the
   *         CBOR-encoded value from the underlying input stream.
   */
  @Override
  public int read1Byte() throws CodecException {
    int r;
    try {
      r = m_is.read();
    } catch (IOException e) {
      throw new CodecException(e);
    }

    if (r == -1) {
      throw new CodecException("bytes too short");
    }
    position++;
    return r;
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

    byte[] bytes = readExactly((int) len);
    return new String(bytes, StandardCharsets.UTF_8);
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
    byte[] bytes = readExactly(2);
    return (bytes[0] & 0xFF) << 8 | (bytes[1] & 0xFF);
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
    byte[] bytes = readExactly(4);
    return ((bytes[0] & 0xFFL) << 24
        | (bytes[1] & 0xFFL) << 16
        | (bytes[2] & 0xFFL) << 8
        | (bytes[3] & 0xFFL)) & 0xffffffffL;
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
    byte[] bytes = readExactly(8);
    return (bytes[0] & 0xFFL) << 56
        | (bytes[1] & 0xFFL) << 48
        | (bytes[2] & 0xFFL) << 40
        | (bytes[3] & 0xFFL) << 32
        | (bytes[4] & 0xFFL) << 24
        | (bytes[5] & 0xFFL) << 16
        | (bytes[6] & 0xFFL) << 8
        | (bytes[7] & 0xFFL);
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
    return read1Byte();
  }

  private void unread(byte[] value) throws CodecException {
    try {
      m_is.unread(value);
    } catch (IOException e) {
      throw new CodecException(e);
    }
    position -= value.length;
  }

  @Override
  protected byte[] readExactly(int len) throws CodecException {
    Args.positive(len, "len");
    byte[] ret = new byte[len];

    try {
      int off = 0;
      while (off < len) {
        int num = m_is.read(ret, off, len - off);
        if (num == -1) {
          if (off > 0) {
            m_is.unread(ret, 0, off);
          }
          throw new CodecException("bytes too short");
        } else {
          off += num;
        }
      }
    } catch (IOException e) {
      throw new CodecException(e);
    }

    position += len;

    return ret;
  }

}
