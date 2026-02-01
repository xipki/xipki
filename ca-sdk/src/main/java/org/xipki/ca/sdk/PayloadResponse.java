// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class PayloadResponse extends SdkResponse {

  /**
   * payload.
   */
  private final byte[] payload;

  public PayloadResponse(byte[] payload) {
    this.payload = payload;
  }

  public byte[] payload() {
    return payload;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeByteString(payload);
  }

  public static PayloadResponse decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("PayloadResponse", decoder, 1);
      return new PayloadResponse(decoder.readByteString());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, PayloadResponse.class), ex);
    }
  }

}
