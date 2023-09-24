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

public class GenCRLRequest extends SdkRequest {

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private final String crlDp;

  public GenCRLRequest(String crlDp) {
    this.crlDp = crlDp;
  }

  public String getCrlDp() {
    return crlDp;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(1);
      encoder.writeTextString(crlDp);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static GenCRLRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(1)) {
        return null;
      }

      return new GenCRLRequest(
          decoder.readTextString());
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + GenCRLRequest.class.getName(), ex);
    }
  }

}
