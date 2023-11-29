// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.CrlReason;
import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class RevokeCertsRequest extends CaIdentifierRequest {

  private final Entry[] entries;

  public RevokeCertsRequest(byte[] issuerCertSha1Fp, X500NameType issuer,
                            byte[] authorityKeyIdentifier, Entry[] entries) {
    super(issuerCertSha1Fp, issuer, authorityKeyIdentifier);
    this.entries = entries;
  }

  public Entry[] getEntries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    super.encode0(encoder, 1);
    encoder.writeObjects(entries);
  }

  public static RevokeCertsRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("RevokeCertsRequest", decoder, 4);
      return new RevokeCertsRequest(
          decoder.readByteString(),
          X500NameType.decode(decoder),
          decoder.readByteString(),
          Entry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, RevokeCertsRequest.class), ex);
    }
  }

  public static class Entry extends SdkEncodable {

    /*
     * Uppercase hex encoded serialNumber.
     */
    private final BigInteger serialNumber;

    private final CrlReason reason;

    /**
     * Epoch time in seconds of invalidity time.
     */
    private final Instant invalidityTime;

    public Entry(BigInteger serialNumber, CrlReason reason, Instant invalidityTime) {
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

    public Instant getInvalidityTime() {
      return invalidityTime;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
      encoder.writeArrayStart(3);
      encoder.writeBigInt(serialNumber);
      encoder.writeEnumObj(reason);
      encoder.writeInstant(invalidityTime);
    }

    public static Entry decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(3)) {
          return null;
        }

        BigInteger serialNumber = decoder.readBigInt();

        String str = decoder.readTextString();
        CrlReason reason = (str == null) ? null : CrlReason.valueOf(str);

        return new Entry(
            serialNumber, reason,
            decoder.readInstant());
      } catch (IOException | RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, Entry.class), ex);
      }
    }

    public static Entry[] decodeArray(CborDecoder decoder) throws DecodeException {
      Integer arrayLen;
      try {
        arrayLen = decoder.readNullOrArrayLength();
      } catch (IOException ex) {
        throw new DecodeException("error decoding " + Entry[].class.getName(), ex);
      }

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
