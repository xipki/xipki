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
 * Response for the operations enrolling certificates and polling certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class EnrollOrPollCertsResponse extends SdkResponse {

  private String transactionId;

  private Long confirmWaitTime;

  private Entry[] entries;

  private byte[][] extraCerts;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public Long getConfirmWaitTime() {
    return confirmWaitTime;
  }

  public void setConfirmWaitTime(Long confirmWaitTime) {
    this.confirmWaitTime = confirmWaitTime;
  }

  public Entry[] getEntries() {
    return entries;
  }

  public void setEntries(Entry[] entries) {
    this.entries = entries;
  }

  public byte[][] getExtraCerts() {
    return extraCerts;
  }

  public void setExtraCerts(byte[][] extraCerts) {
    this.extraCerts = extraCerts;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
    encoder.writeArrayStart(4);
    encoder.writeTextString(transactionId);
    encoder.writeIntObj(confirmWaitTime);
    encoder.writeObjects(entries);
    encoder.writeByteStrings(extraCerts);
  }

  public static EnrollOrPollCertsResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("EnrollOrPollCertsResponse", decoder, 4);
      EnrollOrPollCertsResponse ret = new EnrollOrPollCertsResponse();
      ret.setTransactionId(decoder.readTextString());
      ret.setConfirmWaitTime(decoder.readLongObj());
      ret.setEntries(Entry.decodeArray(decoder));
      ret.setExtraCerts(decoder.readByteStrings());
      return ret;
    } catch (RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, EnrollOrPollCertsResponse.class), ex);
    }
  }

  public static class Entry extends SdkEncodable {

    private final BigInteger id;

    private final ErrorEntry error;

    private final byte[] cert;

    private final byte[] privateKey;

    public Entry(BigInteger id, ErrorEntry error, byte[] cert, byte[] privateKey) {
      this.id = id;
      this.error = error;
      this.cert = cert;
      this.privateKey = privateKey;
    }

    public BigInteger getId() {
      return id;
    }

    public ErrorEntry getError() {
      return error;
    }

    public byte[] getCert() {
      return cert;
    }

    public byte[] getPrivateKey() {
      return privateKey;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(4);
      encoder.writeBigInt(id);
      encoder.writeObject(error);
      encoder.writeByteString(cert);
      encoder.writeByteString(privateKey);
    }

    public static Entry decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(4)) {
          return null;
        }

        return new Entry(
            decoder.readBigInt(),
            ErrorEntry.decode(decoder),
            decoder.readByteString(),
            decoder.readByteString());
      } catch (RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, Entry.class), ex);
      }
    }

    public static Entry[] decodeArray(CborDecoder decoder) throws DecodeException {
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
