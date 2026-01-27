// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class SingleCertSerialEntry extends SdkEncodable {

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
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2).writeBigInt(serialNumber)
        .writeObject(error);
  }

  public static SingleCertSerialEntry decode(CborDecoder decoder)
      throws CodecException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new SingleCertSerialEntry(
          decoder.readBigInt(), ErrorEntry.decode(decoder));
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, SingleCertSerialEntry.class), ex);
    }
  }

  public static SingleCertSerialEntry[] decodeArray(CborDecoder decoder)
      throws CodecException {
    Integer arrayLen = decoder.readNullOrArrayLength();
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
