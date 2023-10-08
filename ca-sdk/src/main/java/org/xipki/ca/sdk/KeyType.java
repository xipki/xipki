// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncodable;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class KeyType implements CborEncodable {

  private final String keyType;

  private final String[] ecCurves;

  public KeyType(String keyType, String[] ecCurves) {
    this.keyType = keyType;
    this.ecCurves = ecCurves;
  }

  public String getKeyType() {
    return keyType;
  }

  public String[] getEcCurves() {
    return ecCurves;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeTextString(keyType);
      encoder.writeTextStrings(ecCurves);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static KeyType decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new KeyType(
          decoder.readTextString(),
          decoder.readTextStrings());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + KeyType.class.getName(), ex);
    }
  }

  public static KeyType[] decodeArray(CborDecoder decoder) throws DecodeException {
    Integer arrayLen = decoder.readNullOrArrayLength(KeyType[].class);
    if (arrayLen == null) {
      return null;
    }

    KeyType[] entries = new KeyType[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      entries[i] = KeyType.decode(decoder);
    }

    return entries;
  }

}
