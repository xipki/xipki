// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

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
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeTextString(tid);
  }

  public static TransactionIdRequest decode(byte[] encoded)
      throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("TransactionIdRequest", decoder, 1);
      return new TransactionIdRequest(decoder.readTextString());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, TransactionIdRequest.class), ex);
    }
  }

}
