// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.codec.Args;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public class KemEncapKey {

  public static final byte ALG_AES_KWP_256 = 1;

  private final String id;

  private final byte alg;

  private final byte[] encapKey;

  public KemEncapKey(String id, byte alg, byte[] encapKey) {
    this.id = Args.notNull(id, "id");
    Args.max(id.length(), "id.length", 255);
    this.alg = alg;
    this.encapKey = Args.notNull(encapKey, "encapKey");
  }

  public static KemEncapKey decode(byte[] encoded) {
    int idLen = encoded[0] & 0xFF;
    int off = 1;
    String id = new String(Arrays.copyOfRange(encoded, off, off + idLen),
                  StandardCharsets.US_ASCII);
    off += idLen;
    byte alg = encoded[off++];
    byte[] encapKey = Arrays.copyOfRange(encoded, off, encoded.length);

    return new KemEncapKey(id, alg, encapKey);
  }

  public String getId() {
    return id;
  }

  public byte getAlg() {
    return alg;
  }

  public byte[] getEncapKey() {
    return encapKey;
  }

  public byte[] getEncoded() {
    byte[] idBytes = id.getBytes(StandardCharsets.US_ASCII);
    byte[] encoded = new byte[1 + idBytes.length + 1 + encapKey.length];
    int off = 0;
    encoded[off++] = (byte) idBytes.length;
    System.arraycopy(idBytes, 0, encoded, off, idBytes.length);
    off += idBytes.length;

    encoded[off++] = alg;
    System.arraycopy(encapKey, 0, encoded, off, encapKey.length);
    return encoded;
  }

}
