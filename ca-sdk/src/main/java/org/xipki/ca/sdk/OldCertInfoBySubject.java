// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class OldCertInfoBySubject extends OldCertInfo {

  private final byte[] subject;

  private final byte[] san;

  public OldCertInfoBySubject(boolean reusePublicKey, byte[] subject, byte[] san) {
    super(reusePublicKey);
    this.subject = subject;
    this.san = san;
  }

  public byte[] getSubject() {
    return subject;
  }

  public byte[] getSan() {
    return san;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(3);
      encoder.writeBoolean(isReusePublicKey());
      encoder.writeByteString(subject);
      encoder.writeByteString(san);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static OldCertInfoBySubject decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      return new OldCertInfoBySubject(
          decoder.readBoolean(),
          decoder.readByteString(),
          decoder.readByteString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + OldCertInfoBySubject.class.getName(), ex);
    }
  }

}
