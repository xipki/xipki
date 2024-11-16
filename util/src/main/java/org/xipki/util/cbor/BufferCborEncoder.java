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

import java.io.EOFException;
import java.io.IOException;

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
  protected void write(byte b) throws IOException {
    if (position >= maxPosition) {
      throw new EOFException("end reached");
    }
    buffer[position++] = b;
  }

  @Override
  protected void write(int b) throws IOException {
    if (position >= maxPosition) {
      throw new EOFException("end reached");
    }
    buffer[position++] = (byte) b;
  }

  @Override
  protected void write(byte[] bytes, int off, int len) throws IOException {
    if (position + len > maxPosition) {
      throw new EOFException("end reached");
    }
    System.arraycopy(bytes, off, buffer, position, len);
    position += len;
  }

  public int getPosition() {
    return position;
  }

}
