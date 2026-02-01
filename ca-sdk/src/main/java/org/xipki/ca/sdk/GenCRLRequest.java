// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class GenCRLRequest extends SdkRequest {

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private final String crlDp;

  public GenCRLRequest(String crlDp) {
    this.crlDp = crlDp;
  }

  public String crlDp() {
    return crlDp;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeTextString(crlDp);
  }

  public static GenCRLRequest decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("GenCRLRequest", decoder, 1);
      return new GenCRLRequest(decoder.readTextString());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, GenCRLRequest.class), ex);
    }
  }

}
