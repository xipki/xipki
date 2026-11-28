// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.encap;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Kem Encap Key.
 * Encoding:
 *
 * len(id):              length of id in bytes, 2 bytes
 * id:                   len(id) bytes
 * alg:                  1 byte
 * len(encapKey):        2 bytes
 * encapKey:             len(encapKey) bytes
 * len(encryptedSecret): 2 bytes
 * encryptedSecret:      len(encryptedSecret) bytes
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KemEncapKey {

  private final String id;

  private final KemEncapsulation encapulation;

  public KemEncapKey(String id, KemEncapsulation encapsulation) {
    this.id = Args.notNull(id, "id");
    Args.max(id.length(), "id.length", 0xFFFF);
    // the id is encoded in US-ASCII: other characters would be replaced by '?'.
    for (int i = 0; i < id.length(); i++) {
      if (id.charAt(i) > 0x7F) {
        throw new IllegalArgumentException("id contains non-ASCII character: " + id);
      }
    }
    this.encapulation = Args.notNull(encapsulation, "encapsulation");
  }

  public static KemEncapKey decode(byte[] encoded) throws CodecException {
    Args.notNull(encoded, "encoded");
    AtomicInteger off = new AtomicInteger(0);
    byte[] idBytes = readBytes(encoded, off);
    String id = new String(idBytes, StandardCharsets.US_ASCII);
    checkRemaining(encoded, off, 1);
    byte alg = encoded[off.getAndIncrement()];
    byte[] encapKey = readBytes(encoded, off);
    byte[] encryptedSecret = readBytes(encoded, off);
    if (off.get() != encoded.length) {
      throw new CodecException("encoded has " + (encoded.length - off.get())
          + " trailing bytes");
    }

    try {
      return new KemEncapKey(id, new KemEncapsulation(alg, encapKey, encryptedSecret));
    } catch (IllegalArgumentException e) {
      throw new CodecException(e.getMessage(), e);
    }
  }

  public String id() {
    return id;
  }

  public KemEncapsulation encapulation() {
    return encapulation;
  }

  public byte[] getEncoded() {
    byte[] idBytes = id.getBytes(StandardCharsets.US_ASCII);
    byte[] encapKey= encapulation.encapKey();
    byte[] encryptedSecret = encapulation.encryptedSecret();
    int len = 7 + idBytes.length + encapKey.length + encryptedSecret.length;
    byte[] encoded = new byte[len];
    AtomicInteger off = new AtomicInteger(0);
    writeBytes(idBytes, encoded, off);
    encoded[off.getAndIncrement()] = encapulation.alg();
    writeBytes(encapKey, encoded, off);
    writeBytes(encryptedSecret, encoded, off);
    return encoded;
  }

  private static void writeBytes(byte[] bytes, byte[] dest, AtomicInteger off) {
    int len = bytes.length;
    dest[off.getAndIncrement()] = (byte) (len >> 8);
    dest[off.getAndIncrement()] = (byte) (len);
    System.arraycopy(bytes, 0, dest, off.get(), len);
    off.addAndGet(len);
  }

  private static byte[] readBytes(byte[] bytes, AtomicInteger off) throws CodecException {
    checkRemaining(bytes, off, 2);
    int len = ((0xFF & bytes[off.getAndIncrement()]) << 8) + (0xFF & bytes[off.getAndIncrement()]);
    // Arrays.copyOfRange() would pad a truncated value with zeros.
    checkRemaining(bytes, off, len);
    return Arrays.copyOfRange(bytes, off.get(), off.addAndGet(len));
  }

  private static void checkRemaining(byte[] bytes, AtomicInteger off, int len)
      throws CodecException {
    if (bytes.length - off.get() < len) {
      throw new CodecException("encoded is truncated: expected " + len + " more bytes at offset "
          + off.get() + ", but only " + (bytes.length - off.get()) + " remain");
    }
  }
}
