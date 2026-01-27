// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 * Response for the operations unsuspending certificates and removing
 * certificates.
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
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeObjects(entries);
  }

  public static UnSuspendOrRemoveCertsResponse decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("UnSuspendOrRemoveCertsResponse", decoder, 1);
      return new UnSuspendOrRemoveCertsResponse(
          SingleCertSerialEntry.decodeArray(decoder));
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, UnSuspendOrRemoveCertsResponse.class), ex);
    }
  }

}
