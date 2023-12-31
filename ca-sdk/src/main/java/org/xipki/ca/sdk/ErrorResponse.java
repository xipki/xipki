// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.pki.ErrorCode;
import org.xipki.util.Args;
import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 * Error response.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
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

  public ErrorCode getCode() {
    return code;
  }

  public String getMessage() {
    return message;
  }

  public String getTransactionId() {
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
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(3);
    encoder.writeTextString(transactionId);
    encoder.writeInt(code.getCode());
    encoder.writeTextString(message);
  }

  public static ErrorResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("ErrorResponse", decoder, 3);

      String tid = decoder.readTextString();
      int code = decoder.readInt();
      ErrorCode errorCode = ErrorCode.ofCode(code);

      return new ErrorResponse(tid, errorCode, decoder.readTextString());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, ErrorResponse.class), ex);
    }
  }

}
