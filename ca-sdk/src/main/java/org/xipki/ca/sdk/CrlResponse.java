// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 * Response containing the CRL.
 *
 * @author Lijun Liao (xipki)
 */

public class CrlResponse extends SdkResponse {

  private final byte[] crl;

  public CrlResponse(byte[] crl) {
    this.crl = crl;
  }

  public byte[] crl() {
    return crl;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeByteString(crl);
  }

  public static CrlResponse decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("CrlResponse", decoder, 1);
      return new CrlResponse(decoder.readByteString());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, CrlResponse.class), ex);
    }
  }

}
