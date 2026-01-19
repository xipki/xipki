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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ByteArrayCborEncoder extends CborEncoder implements AutoCloseable {

  private final ByteArrayOutputStream m_os;

  /**
   * Creates a new {@link ByteArrayCborEncoder} instance with default initial size 32.
   *
   */
  public ByteArrayCborEncoder() {
    this(32);
  }

  /**
   * Creates a new {@link ByteArrayCborEncoder} instance.
   * @param size the initial size.
   *
   */
  public ByteArrayCborEncoder(int size) {
    this.m_os = new ByteArrayOutputStream(Args.min(size, "size", 1));
  }

  public byte[] toByteArray() {
    return m_os.toByteArray();
  }

  @Override
  protected void write(byte b) throws CodecException {
    m_os.write(b);
  }

  @Override
  protected void write(int b) throws CodecException {
    m_os.write(b);
  }

  @Override
  protected void write(byte[] bytes, int off, int len) throws CodecException {
    m_os.write(bytes, off, len);
  }

  @Override
  public void close() throws IOException {
    m_os.close();
  }
}
