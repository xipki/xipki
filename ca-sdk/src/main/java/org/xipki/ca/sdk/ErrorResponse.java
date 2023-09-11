// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.exception.ErrorCode;

/**
 * Error response.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class ErrorResponse extends SdkResponse {

  private String transactionId;

  private ErrorCode code;

  private String message;

  public ErrorResponse() {
  }

  public ErrorResponse(String transactionId, ErrorCode code, String message) {
    this.transactionId = transactionId;
    this.code = code;
    this.message = message;
  }

  public ErrorCode getCode() {
    return code;
  }

  public void setCode(ErrorCode code) {
    this.code = code;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public static ErrorResponse decode(byte[] encoded) {
    return CBOR.parseObject(encoded, ErrorResponse.class);
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

}
