// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.encap;

import org.xipki.util.codec.Args;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * <pre>
 * Encoding:
 *
 * alg:                  1 byte
 * len(id):              length of id in bytes, 2 bytes
 * id:                   len(id) bytes
 * len(encapKey):        2 bytes
 * encapKey:             len(encapKey) bytes
 * len(encryptedSecret): 2 bytes
 * encryptedSecret:      len(encryptedSecret) bytes
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class KemEncapKey {

  private final String id;

  private final KemEncapsulation encapulation;

  public KemEncapKey(String id, KemEncapsulation encapsulation) {
    this.id = Args.notNull(id, "id");
    Args.max(id.length(), "id.length", 0xFFFF);
    this.encapulation = Args.notNull(encapsulation, "encapsulation");
  }

  public static KemEncapKey decode(byte[] encoded) {
    AtomicInteger off = new AtomicInteger(0);
    byte[] idBytes = readBytes(encoded, off);
    String id = new String(idBytes, StandardCharsets.US_ASCII);
    byte alg = encoded[off.getAndIncrement()];
    byte[] encapKey = readBytes(encoded, off);
    byte[] encryptedSecret = readBytes(encoded, off);
    return new KemEncapKey(id,
        new KemEncapsulation(alg, encapKey, encryptedSecret));
  }

  public String getId() {
    return id;
  }

  public KemEncapsulation getEncapulation() {
    return encapulation;
  }

  public byte[] getEncoded() {
    byte[] idBytes = id.getBytes(StandardCharsets.US_ASCII);
    byte[] encapKey= encapulation.getEncapKey();
    byte[] encryptedSecret = encapulation.getEncryptedSecret();
    int len = 7 + idBytes.length + encapKey.length +
              encryptedSecret.length;
    byte[] encoded = new byte[len];
    AtomicInteger off = new AtomicInteger(0);
    writeBytes(idBytes, encoded, off);
    encoded[off.getAndIncrement()] = encapulation.getAlg();
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

  private static byte[] readBytes(byte[] bytes, AtomicInteger off) {
    int len = ((0xFF & bytes[off.getAndIncrement()]) << 8) +
               (0xFF & bytes[off.getAndIncrement()]);
    return Arrays.copyOfRange(bytes, off.get(), off.addAndGet(len));
  }

}
