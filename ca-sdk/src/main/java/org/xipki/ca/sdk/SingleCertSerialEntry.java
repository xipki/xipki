// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncodable;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class SingleCertSerialEntry implements CborEncodable {

  /*
   * Uppercase hex encoded serialNumber.
   */
  private final BigInteger serialNumber;

  private final ErrorEntry error;

  public SingleCertSerialEntry(BigInteger serialNumber, ErrorEntry error) {
    this.serialNumber = serialNumber;
    this.error = error;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public ErrorEntry getError() {
    return error;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeByteString(serialNumber);
      encoder.writeObject(error);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static SingleCertSerialEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new SingleCertSerialEntry(
          decoder.readBigInt(),
          ErrorEntry.decode(decoder));
    } catch (IOException | IllegalArgumentException ex) {
      throw new DecodeException("error decoding " + SingleCertSerialEntry.class.getName(), ex);
    }
  }

  public static SingleCertSerialEntry[] decodeArray(CborDecoder decoder) throws DecodeException {
    Integer arrayLen = decoder.readNullOrArrayLength(SingleCertSerialEntry[].class);
    if (arrayLen == null) {
      return null;
    }

    SingleCertSerialEntry[] entries = new SingleCertSerialEntry[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      entries[i] = SingleCertSerialEntry.decode(decoder);
    }

    return entries;
  }

}
