// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.password;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborEncoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.io.IOException;

/**
 * @author Lijun Liao (xipki)
 */
public class PBECipherBlob {

  private final int algo;

  private final int iterations;

  private final byte[] salt;

  private final byte[] cipherText;

  public PBECipherBlob(int algo, int iterations, byte[] salt,
                       byte[] cipherText) {
    this.algo = algo;
    this.iterations = iterations;
    this.salt = salt;
    this.cipherText = cipherText;
  }

  public int algo() {
    return algo;
  }

  public int iterations() {
    return iterations;
  }

  public byte[] salt() {
    return salt;
  }

  public byte[] cipherText() {
    return cipherText;
  }

  public byte[] getEncoded() throws CodecException {
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()) {
      encode(encoder);
      return encoder.toByteArray();
    } catch (IOException e) {
      throw new CodecException(e);
    }
  }

  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(5);
    encoder.writeInt(1); // version 1
    encoder.writeInt(algo);
    encoder.writeInt(iterations);
    encoder.writeByteString(salt);
    encoder.writeByteString(cipherText);
  }

  public static PBECipherBlob decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      return decode(decoder);
    }
  }

  public static PBECipherBlob decode(CborDecoder decoder)
      throws CodecException {
    int arrayLen = decoder.readArrayLength();
    int version = decoder.readInt();
    if (version != 1) {
      throw new CodecException("invalid version " + version);
    }

    if (arrayLen != 5) {
      throw new CodecException("invalid arrayLen " + arrayLen);
    }

    int algo = decoder.readInt();
    int iterations = decoder.readInt();
    byte[] salt = decoder.readByteString();
    byte[] ciphertext = decoder.readByteString();
    return new PBECipherBlob(algo, iterations, salt, ciphertext);
  }

}
