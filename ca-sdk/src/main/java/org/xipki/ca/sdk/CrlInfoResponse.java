// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 * CrlInfo Response payload.
 *
 * @author Lijun Liao (xipki)
 */

public class CrlInfoResponse extends SdkResponse {

  private final byte[] crlInfo;

  public CrlInfoResponse(byte[] crlInfo) {
    this.crlInfo = crlInfo;
  }

  public byte[] crlInfo() {
    return crlInfo;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeByteString(crlInfo);
  }

  public static CrlInfoResponse decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("CrlInfoResponse", decoder, 1);
      return new CrlInfoResponse(decoder.readByteString());
    } catch (RuntimeException ex) {
      throw new CodecException(buildDecodeErrMessage(ex, CrlInfoResponse.class), ex);
    }
  }

}
