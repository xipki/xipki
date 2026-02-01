// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.cbor;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Lijun Liao (xipki)
 */
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
  protected void write(byte b) throws CodecException {
    try {
      m_os.write(b);
    } catch (IOException e) {
      throw new CodecException.CodecIOException(e);
    }
  }

  @Override
  protected void write(int b) throws CodecException {
    try {
      m_os.write(b);
    } catch (IOException e) {
      throw new CodecException.CodecIOException(e);
    }
  }

  @Override
  protected void write(byte[] bytes, int off, int len) throws CodecException {
    try {
      m_os.write(bytes, off, len);
    } catch (IOException e) {
      throw new CodecException.CodecIOException(e);
    }
  }

  @Override
  public void close() throws Exception {
    m_os.close();
  }

}
