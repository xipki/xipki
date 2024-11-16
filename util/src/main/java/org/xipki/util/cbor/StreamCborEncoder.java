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

import java.io.IOException;
import java.io.OutputStream;

public class StreamCborEncoder extends CborEncoder implements AutoCloseable {

  private final OutputStream m_os;

  /**
   * Creates a new {@link StreamCborEncoder} instance.
   * @param os the output stream to which the data will be written.
   *
   */
  public StreamCborEncoder(OutputStream os) {
    this.m_os = Args.notNull(os, "os");
  }

  @Override
  protected void write(byte b) throws IOException {
    m_os.write(b);
  }

  @Override
  protected void write(int b) throws IOException {
    m_os.write(b);
  }

  @Override
  protected void write(byte[] bytes, int off, int len) throws IOException {
    m_os.write(bytes, off, len);
  }

  @Override
  public void close() throws Exception {
    m_os.close();
  }

}
