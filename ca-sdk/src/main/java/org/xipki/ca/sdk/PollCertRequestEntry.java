// Copyright (c) 2013-2023 xipki. All rights reserved.
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

public class PollCertRequestEntry extends SdkEncodable {

  /*
   * In SCEP: this field is null.
   */
  private final BigInteger id;

  private final X500NameType subject;

  public PollCertRequestEntry(BigInteger id, X500NameType subject) {
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

  public static PollCertRequestEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new PollCertRequestEntry(
          decoder.readBigInt(),
          X500NameType.decode(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, PollCertRequestEntry.class), ex);
    }
  }

  public static PollCertRequestEntry[] decodeArray(CborDecoder decoder) throws DecodeException {
    Integer arrayLen = decoder.readNullOrArrayLength(PollCertRequestEntry[].class);
    if (arrayLen == null) {
      return null;
    }

    PollCertRequestEntry[] entries = new PollCertRequestEntry[arrayLen];
    for (int i = 0; i < arrayLen; i++) {
      entries[i] = PollCertRequestEntry.decode(decoder);
    }

    return entries;
  }

}
