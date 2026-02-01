// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.cbor;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

/**
 * @author Lijun Liao (xipki)
 */
public class BufferCborEncoder extends CborEncoder {

  private final byte[] buffer;

  private final int maxPosition; // exclusive

  private int position;

  public BufferCborEncoder(byte[] buffer) {
    this.buffer = Args.notNull(buffer, "buffer");
    this.position = 0;
    this.maxPosition = buffer.length;

  }

  /**
   * Creates a new {@link BufferCborEncoder} instance.
   * @param buffer the buffer to which the data will be written.
   * @param offset offset of the buffer.
   * @param maxLen maximal length of data to be written.
   */
  public BufferCborEncoder(byte[] buffer, int offset, int maxLen) {
    this.buffer = Args.notNull(buffer, "buffer");

    if (offset < 0 || offset > buffer.length - 1) {
      throw new IllegalArgumentException("invalid offset " + offset);
    }

    if (maxLen < 1 || offset + maxLen > buffer.length) {
      throw new IllegalArgumentException("invalid maxLen " + maxLen);
    }

    this.position = offset;
    this.maxPosition = offset + maxLen;
  }

  @Override
  protected void write(byte b) throws CodecException {
    if (position >= maxPosition) {
      throw new CodecException.CodecIOException("EOF reached");
    }
    buffer[position++] = b;
  }

  @Override
  protected void write(int b) throws CodecException {
    if (position >= maxPosition) {
      throw new CodecException.CodecIOException("EOF reached");
    }
    buffer[position++] = (byte) b;
  }

  @Override
  protected void write(byte[] bytes, int off, int len) throws CodecException {
    if (position + len > maxPosition) {
      throw new CodecException.CodecIOException("EOF reached");
    }
    System.arraycopy(bytes, off, buffer, position, len);
    position += len;
  }

  public int position() {
    return position;
  }

}
