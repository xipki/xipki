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

public class PollCertRequest extends CaIdentifierRequest {

  private final String transactionId;

  private final Entry[] entries;

  public PollCertRequest(byte[] issuerCertSha1Fp, X500NameType issuer, byte[] authorityKeyIdentifier,
                         String transactionId, Entry[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
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
    super.encode0(encoder, 2);
    encoder.writeTextString(transactionId);
    encoder.writeObjects(entries);
  }

  public static PollCertRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("PollCertRequest", decoder, 5);
      return new PollCertRequest(
          decoder.readByteString(),
          X500NameType.decode(decoder),
          decoder.readByteString(),
          decoder.readTextString(),
          Entry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, PollCertRequest.class), ex);
    }
  }

  public static class Entry extends SdkEncodable {

    /*
     * In SCEP: this field is null.
     */
    private final BigInteger id;

    private final X500NameType subject;

    public Entry(BigInteger id, X500NameType subject) {
      this.id = id;
      this.subject = subject;
    }

    public BigInteger getId() {
      return id;
    }

    public X500NameType getSubject() {
      return subject;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
      encoder.writeArrayStart(2);
      encoder.writeBigInt(id);
      encoder.writeObject(subject);
    }

    public static Entry decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(2)) {
          return null;
        }

        return new Entry(
            decoder.readBigInt(),
            X500NameType.decode(decoder));
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
