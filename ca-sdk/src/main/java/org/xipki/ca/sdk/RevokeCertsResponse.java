// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncoder;

import java.io.ByteArrayInputStream;
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
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(1);
      encoder.writeObjects(entries);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static RevokeCertsResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(1)) {
        return null;
      }

      return new RevokeCertsResponse(
          SingleCertSerialEntry.decodeArray(decoder));
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + RevokeCertsResponse.class.getName(), ex);
    }
  }


}
