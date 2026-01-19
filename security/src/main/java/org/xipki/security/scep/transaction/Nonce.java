// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.transaction;

import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.RandomUtil;

import java.util.Arrays;

/**
 * Nonce.
 *
 * @author Lijun Liao (xipki)
 */

public class Nonce {

  private static final int NONCE_LEN = 16;

  private final byte[] bytes;

  private Nonce(byte[] bytes, boolean cloneBytes) {
    Args.notNull(bytes, "bytes");
    if (bytes.length != 16) {
      throw new IllegalArgumentException("bytes.length is not of 16");
    }
    this.bytes = cloneBytes ? Arrays.copyOf(bytes, bytes.length) : bytes;
  }

  public Nonce(byte[] bytes) {
    this(bytes, true);
  }

  public byte[] getBytes() {
    return Arrays.copyOf(bytes, bytes.length);
  }

  public static Nonce randomNonce() {
    return new Nonce(RandomUtil.nextBytes(NONCE_LEN), false);
  }

}
