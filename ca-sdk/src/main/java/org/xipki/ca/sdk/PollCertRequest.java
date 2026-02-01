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

public class PollCertRequest extends CaIdentifierRequest {

  private final String transactionId;

  private final Entry[] entries;

  public PollCertRequest(byte[] issuerCertSha1Fp, X500NameType issuer,
                         byte[] authorityKeyIdentifier, String transactionId,
                         Entry[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
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
    super.encode0(encoder, 2);
    encoder.writeTextString(transactionId);
    encoder.writeObjects(entries);
  }

  public static PollCertRequest decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("PollCertRequest", decoder, 5);
      return new PollCertRequest(
          decoder.readByteString(),
          X500NameType.decode(decoder),
          decoder.readByteString(),
          decoder.readTextString(),
          Entry.decodeArray(decoder));
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, PollCertRequest.class), ex);
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

    public BigInteger id() {
      return id;
    }

    public X500NameType subject() {
      return subject;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws CodecException {
      encoder.writeArrayStart(2).writeBigInt(id).writeObject(subject);
    }

    public static Entry decode(CborDecoder decoder) throws CodecException {
      try {
        if (decoder.readNullOrArrayLength(2)) {
          return null;
        }

        return new Entry(decoder.readBigInt(), X500NameType.decode(decoder));
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
