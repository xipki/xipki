package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;
import org.xipki.util.exception.OperationException;

public class ErrorResponse extends SdkResponse {

  private String transactionId;

  private OperationException.ErrorCode code;

  private String message;

  public ErrorResponse() {
  }

  public ErrorResponse(String transactionId, OperationException.ErrorCode code, String message) {
    this.transactionId = transactionId;
    this.code = code;
    this.message = message;
  }

  public OperationException.ErrorCode getCode() {
    return code;
  }

  public void setCode(OperationException.ErrorCode code) {
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
    return JSON.parseObject(encoded, ErrorResponse.class);
  }

}
