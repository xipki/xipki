// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

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

  @Override
  protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
    encoder.writeArrayStart(1);
    encoder.writeByteString(crl);
  }

  public static CrlResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("CrlResponse", decoder, 1);
      return new CrlResponse(decoder.readByteString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, CrlResponse.class), ex);
    }
  }

}
