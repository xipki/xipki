// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.ByteArrayCborDecoder;
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

public class ConfirmCertsRequest extends SdkRequest {

  private final String transactionId;

  private final Entry[] entries;

  public ConfirmCertsRequest(String transactionId, Entry[] entries) {
    this.transactionId = transactionId;
    this.entries = entries;
  }

  public String getTransactionId() {
    return transactionId;
  }

  public Entry[] getEntries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(2);
    encoder.writeTextString(transactionId);
    encoder.writeObjects(entries);
  }

  public static ConfirmCertsRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("ConfirmCertsRequest", decoder, 2);
      return new ConfirmCertsRequest(
          decoder.readTextString(),
          Entry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, ConfirmCertsRequest.class), ex);
    }
  }

  public static class Entry extends SdkEncodable {

    private final boolean accept;

    private final BigInteger certReqId;

    /**
     * certHash.
     */
    private final byte[] certhash;

    public Entry(boolean accept, BigInteger certReqId, byte[] certhash) {
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

    public static Entry decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(3)) {
          return null;
        }

        return new Entry(
            decoder.readBoolean(),
            decoder.readBigInt(),
            decoder.readByteString());
      } catch (IOException | RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, Entry.class), ex);
      }
    }

    public static Entry[] decodeArray(CborDecoder decoder) throws DecodeException {
      Integer arrayLen = decoder.readNullOrArrayLength(Entry[].class);
      if (arrayLen == null) {
        return null;
      }

      Entry[] entries = new Entry[arrayLen];
      for (int i = 0; i < arrayLen; i++) {
        entries[i] = Entry.decode(decoder);
      }

      return entries;
    }

  }
}
