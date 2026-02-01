// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.misc;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Lijun Liao (xipki)
 */
public class NopOutputStream extends OutputStream {

  public static final NopOutputStream INSTANCE = new NopOutputStream();

  private NopOutputStream() {
  }

  @Override
  public void write(int b) throws IOException {
  }

  @Override
  public void write(byte[] b) throws IOException {
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
  }

}
