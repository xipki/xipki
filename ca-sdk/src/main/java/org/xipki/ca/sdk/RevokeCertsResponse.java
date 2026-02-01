// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 * Response for the operation revoking certificates.
 *
 * @author Lijun Liao (xipki)
 */

public class RevokeCertsResponse extends SdkResponse {

  private final SingleCertSerialEntry[] entries;

  public RevokeCertsResponse(SingleCertSerialEntry[] entries) {
    this.entries = entries;
  }

  public SingleCertSerialEntry[] entries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeObjects(entries);
  }

  public static RevokeCertsResponse decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("RevokeCertsResponse", decoder, 1);
      return new RevokeCertsResponse(
          SingleCertSerialEntry.decodeArray(decoder));
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, RevokeCertsResponse.class), ex);
    }
  }

}
