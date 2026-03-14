// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.sign;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * X509 Signature Value
 * <pre>
 * len(id),  1 byte || id,  len(id) bytes ||
 * len(sig), 1 byte || sig, len(sig) bytes
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class KemHmacSignature {

  private final String id;

  private final byte[] idBytes;

  private final byte[] signature;

  public KemHmacSignature(String id, byte[] signature) {
    this.id = Args.notNull(id, "id");
    this.idBytes = id.getBytes(StandardCharsets.UTF_8);
    this.signature = Args.notEmpty(signature, "signature");

    Args.range(idBytes.length, "idBytes.length", 1, 255);
    Args.range(signature.length, "signature.length", 1, 255);
  }

  public KemHmacSignature(byte[] idBytes, byte[] signature) {
    this.idBytes = Args.notNull(idBytes, "idBytes");
    this.id = new String(idBytes, StandardCharsets.UTF_8);
    this.signature = Args.notEmpty(signature, "signature");

    Args.range(idBytes.length, "idBytes.length", 1, 255);
    Args.range(signature.length, "signature.length", 1, 255);
  }

  public String id() {
    return id;
  }

  public byte[] signature() {
    return signature;
  }

  public byte[] getEncoded() {
    byte[] ret = new byte[1 + idBytes.length + 1 + signature.length];

    int off = 0;
    ret[off++] = (byte) idBytes.length;
    System.arraycopy(idBytes, 0, ret, off, idBytes.length);
    off += idBytes.length;

    ret[off++] = (byte) signature.length;
    System.arraycopy(signature, 0, ret, off, signature.length);
    return ret;
  }

  public static KemHmacSignature decode(byte[] encoded) throws CodecException {
    int len = Args.notNull(encoded, "encoded").length;
    if (len < 3) {
      throw new CodecException("invalid encoded KemHmacSignature");
    }

    int off = 0;
    int idLen = 0xFF & encoded[off++];

    if (len < off + idLen + 2) {
      throw new CodecException("invalid encoded KemHmacSignature");
    }
    byte[] idBytes = Arrays.copyOfRange(encoded, off, off + idLen);
    off += idLen;

    int sigLen = 0xFF & encoded[off++];
    if (len != off + sigLen) {
      throw new CodecException("invalid encoded KemHmacSignature");
    }
    byte[] sig = Arrays.copyOfRange(encoded, off, len);
    return new KemHmacSignature(idBytes, sig);
  }

}
