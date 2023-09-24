// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;
import org.xipki.util.exception.ErrorCode;

import java.io.ByteArrayInputStream;
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
    this.code = code;
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
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(3);
      encoder.writeTextString(transactionId);
      encoder.writeEnumObj(code);
      encoder.writeTextString(message);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static ErrorResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(encoded))){
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      String tid = decoder.readTextString();
      String str = decoder.readTextString();
      ErrorCode errorCode = str == null ? null : ErrorCode.valueOf(str);

      return new ErrorResponse(
          tid, errorCode,
          decoder.readTextString());
    } catch (IOException | IllegalArgumentException ex) {
      throw new DecodeException("error decoding " + ErrorResponse.class.getName(), ex);
    }
  }

}
