// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.math.BigInteger;

/**
 * Response for the operations enrolling certificates and polling certificates.
 *
 * @author Lijun Liao (xipki)
 */

public class EnrollOrPollCertsResponse extends SdkResponse {

  private String transactionId;

  private Long confirmWaitTime;

  private Entry[] entries;

  private byte[][] extraCerts;

  public String transactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public Long confirmWaitTime() {
    return confirmWaitTime;
  }

  public void setConfirmWaitTime(Long confirmWaitTime) {
    this.confirmWaitTime = confirmWaitTime;
  }

  public Entry[] entries() {
    return entries;
  }

  public void setEntries(Entry[] entries) {
    this.entries = entries;
  }

  public byte[][] extraCerts() {
    return extraCerts;
  }

  public void setExtraCerts(byte[][] extraCerts) {
    this.extraCerts = extraCerts;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(4).writeTextString(transactionId)
        .writeLongObj(confirmWaitTime).writeObjects(entries)
        .writeByteStrings(extraCerts);
  }

  public static EnrollOrPollCertsResponse decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("EnrollOrPollCertsResponse", decoder, 4);
      EnrollOrPollCertsResponse ret = new EnrollOrPollCertsResponse();
      ret.setTransactionId(decoder.readTextString());
      ret.setConfirmWaitTime(decoder.readLongObj());
      ret.setEntries(Entry.decodeArray(decoder));
      ret.setExtraCerts(decoder.readByteStrings());
      return ret;
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, EnrollOrPollCertsResponse.class), ex);
    }
  }

  public static class Entry extends SdkEncodable {

    private final BigInteger id;

    private final ErrorEntry error;

    private final byte[] cert;

    private final byte[] privateKey;

    public Entry(BigInteger id, ErrorEntry error, byte[] cert,
                 byte[] privateKey) {
      this.id = id;
      this.error = error;
      this.cert = cert;
      this.privateKey = privateKey;
    }

    public BigInteger id() {
      return id;
    }

    public ErrorEntry error() {
      return error;
    }

    public byte[] cert() {
      return cert;
    }

    public byte[] privateKey() {
      return privateKey;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws CodecException {
      encoder.writeArrayStart(4).writeBigInt(id).writeObject(error)
          .writeByteString(cert).writeByteString(privateKey);
    }

    public static Entry decode(CborDecoder decoder) throws CodecException {
      try {
        if (decoder.readNullOrArrayLength(4)) {
          return null;
        }

        return new Entry(decoder.readBigInt(), ErrorEntry.decode(decoder),
            decoder.readByteString(), decoder.readByteString());
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
