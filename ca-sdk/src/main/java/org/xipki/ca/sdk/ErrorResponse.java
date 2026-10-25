// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.exception.ErrorCode;

/**
 * Error Response payload.
 *
 * @author Lijun Liao (xipki)
 */
public class ErrorResponse extends SdkResponse {

  private final String transactionId;

  private final ErrorCode code;

  private final String message;

  public ErrorResponse(String transactionId, ErrorCode code, String message) {
    this.transactionId = transactionId;
    this.code = Args.notNull(code, "code");
    this.message = message;
  }

  public ErrorCode code() {
    return code;
  }

  public String message() {
    return message;
  }

  public String transactionId() {
    return transactionId;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    if (transactionId != null) {
      sb.append("tid=").append(transactionId).append(", ");
    }
    sb.append(code);
    if (message != null) {
      sb.append(", ").append(message);
    }
    return sb.toString();
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(3).writeTextString(transactionId)
        .writeInt(code.code()).writeTextString(message);
  }

  public static ErrorResponse decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("ErrorResponse", decoder, 3);

      String tid = decoder.readTextString();
      int code = decoder.readInt();
      ErrorCode errorCode = ErrorCode.ofCode(code);

      return new ErrorResponse(tid, errorCode, decoder.readTextString());
    } catch (RuntimeException ex) {
      throw new CodecException(buildDecodeErrMessage(ex, ErrorResponse.class), ex);
    }
  }

}
