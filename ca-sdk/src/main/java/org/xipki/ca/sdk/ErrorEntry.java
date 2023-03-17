// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.exception.ErrorCode;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ErrorEntry {

  private int code;

  private String message;

  private ErrorEntry() {
  }

  public ErrorEntry(ErrorCode code, String message) {
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

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    try {
      sb.append(ErrorCode.ofCode(code).name());
    } catch (Exception e) {
      sb.append("Unknown code ").append(code);
    }

    if (message != null) {
      sb.append(", message: ").append(message);
    }
    return sb.toString();
  }

}
