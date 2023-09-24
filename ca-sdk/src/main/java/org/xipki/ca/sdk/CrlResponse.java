// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Response containing the CRL.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CrlResponse extends SdkResponse {

  private final byte[] crl;

  public CrlResponse(byte[] crl) {
    this.crl = crl;
  }

  public byte[] getCrl() {
    return crl;
  }

  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(1);
      encoder.writeByteString(crl);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static CrlResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(1)) {
        return null;
      }

      return new CrlResponse(
          decoder.readByteString());
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + CrlResponse.class.getName(), ex);
    }
  }

}
