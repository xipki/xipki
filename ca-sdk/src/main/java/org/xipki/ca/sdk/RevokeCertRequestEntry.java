// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.CrlReason;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncodable;
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

public class RevokeCertRequestEntry implements CborEncodable {

  /*
   * Uppercase hex encoded serialNumber.
   */
  private final BigInteger serialNumber;

  private final CrlReason reason;

  /**
   * Epoch time in seconds of invalidity time.
   */
  private final Long invalidityTime;

  public RevokeCertRequestEntry(BigInteger serialNumber, CrlReason reason, Long invalidityTime) {
    this.serialNumber = serialNumber;
    this.reason = reason;
    this.invalidityTime = invalidityTime;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public CrlReason getReason() {
    return reason;
  }

  public Long getInvalidityTime() {
    return invalidityTime;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(3);
      encoder.writeByteString(serialNumber);
      encoder.writeEnumObj(reason);
      encoder.writeIntObj(invalidityTime);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static RevokeCertRequestEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      BigInteger serialNumber = decoder.readBigInt();

      String str = decoder.readTextString();
      CrlReason reason = (str == null) ? null : CrlReason.valueOf(str);

      return new RevokeCertRequestEntry(
          serialNumber, reason,
          decoder.readIntObj());
    } catch (IOException | IllegalArgumentException ex) {
      throw new DecodeException("error decoding " + RevokeCertRequestEntry.class.getName(), ex);
    }
  }

  public static RevokeCertRequestEntry[] decodeArray(CborDecoder decoder) throws DecodeException {
    Integer arrayLen;
    try {
      arrayLen = decoder.readNullOrArrayLength();
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + RevokeCertRequestEntry[].class.getName(), ex);
    }

    if (arrayLen == null) {
      return null;
    }

    RevokeCertRequestEntry[] entries = new RevokeCertRequestEntry[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      entries[i] = RevokeCertRequestEntry.decode(decoder);
    }

    return entries;
  }

}
