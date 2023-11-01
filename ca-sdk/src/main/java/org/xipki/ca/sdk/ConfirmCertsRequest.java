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
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class ConfirmCertsRequest extends SdkRequest {

  private final String transactionId;

  private final ConfirmCertRequestEntry[] entries;

  public ConfirmCertsRequest(String transactionId, ConfirmCertRequestEntry[] entries) {
    this.transactionId = transactionId;
    this.entries = entries;
  }

  public String getTransactionId() {
    return transactionId;
  }

  public ConfirmCertRequestEntry[] getEntries() {
    return entries;
  }

  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeTextString(transactionId);
      encoder.writeObjects(entries);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static ConfirmCertsRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("ConfirmCertsRequest", decoder, 2);
      return new ConfirmCertsRequest(
          decoder.readTextString(),
          ConfirmCertRequestEntry.decodeArray(decoder));
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + ConfirmCertsRequest.class.getName(), ex);
    }
  }

}
