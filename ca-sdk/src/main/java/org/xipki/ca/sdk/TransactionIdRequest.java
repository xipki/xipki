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

public class TransactionIdRequest extends SdkRequest {

  private final String tid;

  public TransactionIdRequest(String tid) {
    this.tid = tid;
  }

  public String getTid() {
    return tid;
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(1);
      encoder.writeTextString(tid);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static TransactionIdRequest decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("TransactionIdRequest", decoder, 1);
      return new TransactionIdRequest(decoder.readTextString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + TransactionIdRequest.class.getName(), ex);
    }
  }

}
