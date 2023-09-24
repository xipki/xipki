// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncodable;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class PollCertRequestEntry implements CborEncodable {

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
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeByteString(id);
      encoder.writeObject(subject);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static PollCertRequestEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new PollCertRequestEntry(
          decoder.readBigInt(),
          X500NameType.decode(decoder));
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + PollCertRequestEntry.class.getName(), ex);
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
