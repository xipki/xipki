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
 * Response for the operations unrevoking certificates and removing certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class UnSuspendOrRemoveCertsResponse extends SdkResponse {

  private final SingleCertSerialEntry[] entries;

  public UnSuspendOrRemoveCertsResponse(SingleCertSerialEntry[] entries) {
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

  public static UnSuspendOrRemoveCertsResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("UnSuspendOrRemoveCertsResponse", decoder, 1);
      return new UnSuspendOrRemoveCertsResponse(
          SingleCertSerialEntry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, UnSuspendOrRemoveCertsResponse.class), ex);
    }
  }

}
