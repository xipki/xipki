// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;

import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class ConfirmCertRequestEntry extends SdkEncodable {

  private final boolean accept;

  private final BigInteger certReqId;

  /**
   * certHash.
   */
  private final byte[] certhash;

  public ConfirmCertRequestEntry(boolean accept, BigInteger certReqId, byte[] certhash) {
    this.accept = accept;
    this.certhash = certhash;
    this.certReqId = certReqId;
  }

  public BigInteger getCertReqId() {
    return certReqId;
  }

  public byte[] getCerthash() {
    return certhash;
  }

  public boolean isAccept() {
    return accept;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException {
    encoder.writeArrayStart(3);
    encoder.writeBoolean(accept);
    encoder.writeBigInt(certReqId);
    encoder.writeByteString(certhash);
  }

  public static ConfirmCertRequestEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      return new ConfirmCertRequestEntry(
          decoder.readBoolean(),
          decoder.readBigInt(),
          decoder.readByteString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, ConfirmCertRequestEntry.class), ex);
    }
  }

  public static ConfirmCertRequestEntry[] decodeArray(CborDecoder decoder) throws DecodeException {
    Integer arrayLen = decoder.readNullOrArrayLength(ConfirmCertRequestEntry[].class);
    if (arrayLen == null) {
      return null;
    }

    ConfirmCertRequestEntry[] entries = new ConfirmCertRequestEntry[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      entries[i] = ConfirmCertRequestEntry.decode(decoder);
    }

    return entries;
  }

}
