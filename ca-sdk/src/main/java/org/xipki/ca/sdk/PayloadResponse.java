// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.ByteArrayCborDecoder;
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

public class PayloadResponse extends SdkResponse {

  /**
   * payload.
   */
  private final byte[] payload;

  public PayloadResponse(byte[] payload) {
    this.payload = payload;
  }

  public byte[] getPayload() {
    return payload;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(1);
      encoder.writeByteString(payload);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static PayloadResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("PayloadResponse", decoder, 1);
      return new PayloadResponse(decoder.readByteString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + PayloadResponse.class.getName(), ex);
    }
  }

}
