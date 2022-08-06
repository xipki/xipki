package org.xipki.ca.sdk;

import org.xipki.util.exception.OperationException;

public class ErrorEntry {

  private int code;

  private String message;

  private ErrorEntry() {
  }

  public ErrorEntry(OperationException.ErrorCode code, String message) {
    this.code = code.getCode();
    this.message = message;
  }

  public ErrorEntry(int code, String message) {
    this.code = code;
    this.message = message;
  }

  public int getCode() {
    return code;
  }

  public void setCode(int code) {
    this.code = code;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

}
