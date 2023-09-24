// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.ByteArrayInputStream;
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
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static PayloadResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(1)) {
        return null;
      }

      return new PayloadResponse(
          decoder.readByteString());
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + PayloadResponse.class.getName(), ex);
    }
  }

}
