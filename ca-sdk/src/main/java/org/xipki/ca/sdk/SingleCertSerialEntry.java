// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;
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
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(2);
    encoder.writeBigInt(serialNumber);
    encoder.writeObject(error);
  }

  public static SingleCertSerialEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new SingleCertSerialEntry(
          decoder.readBigInt(),
          ErrorEntry.decode(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, SingleCertSerialEntry.class), ex);
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
