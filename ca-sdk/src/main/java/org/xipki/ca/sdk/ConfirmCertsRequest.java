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
 */

public class ConfirmCertsRequest extends SdkRequest {

  private final String transactionId;

  private final Entry[] entries;

  public ConfirmCertsRequest(String transactionId, Entry[] entries) {
    this.transactionId = transactionId;
    this.entries = entries;
  }

  public String transactionId() {
    return transactionId;
  }

  public Entry[] entries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2)
        .writeTextString(transactionId).writeObjects(entries);
  }

  public static ConfirmCertsRequest decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("ConfirmCertsRequest", decoder, 2);
      return new ConfirmCertsRequest(
          decoder.readTextString(), Entry.decodeArray(decoder));
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, ConfirmCertsRequest.class), ex);
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

    public BigInteger certReqId() {
      return certReqId;
    }

    public byte[] certhash() {
      return certhash;
    }

    public boolean isAccept() {
      return accept;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws CodecException {
      encoder.writeArrayStart(3);
      encoder.writeBoolean(accept);
      encoder.writeBigInt(certReqId);
      encoder.writeByteString(certhash);
    }

    public static Entry decode(CborDecoder decoder) throws CodecException {
      try {
        if (decoder.readNullOrArrayLength(3)) {
          return null;
        }

        return new Entry(
            decoder.readBoolean(),
            decoder.readBigInt(),
            decoder.readByteString());
      } catch (RuntimeException ex) {
        throw new CodecException(buildDecodeErrMessage(ex, Entry.class), ex);
      }
    }

    public static Entry[] decodeArray(CborDecoder decoder)
        throws CodecException {
      Integer arrayLen = decoder.readNullOrArrayLength();
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
