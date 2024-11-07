// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 * Response for the operation revoking certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class RevokeCertsResponse extends SdkResponse {

  private final SingleCertSerialEntry[] entries;

  public RevokeCertsResponse(SingleCertSerialEntry[] entries) {
    this.entries = entries;
  }

  public SingleCertSerialEntry[] getEntries() {
    return entries;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(1);
    encoder.writeObjects(entries);
  }

  public static RevokeCertsResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("RevokeCertsResponse", decoder, 1);
      return new RevokeCertsResponse(
          SingleCertSerialEntry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, RevokeCertsResponse.class), ex);
    }
  }

}
