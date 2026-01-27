// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.exception;

/**
 * Operation exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OperationException extends Exception {

  private final ErrorCode errorCode;

  private final String errorMessage;

  public OperationException(ErrorCode errorCode) {
    super(String.format("error code: %s", errorCode));
    this.errorCode = errorCode;
    this.errorMessage = null;
  }

  public OperationException(ErrorCode errorCode, String errorMessage) {
    super(String.format("error code: %s, error message: %s",
        errorCode, errorMessage));
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
  }

  public OperationException(ErrorCode errorCode, Throwable cause) {
    this(errorCode, cause.getMessage(), cause);
  }

  public OperationException(ErrorCode errorCode, String message,
                            Throwable cause) {
    super(String.format("error code: %s, error message: %s",
        errorCode, message), cause);
    this.errorMessage = cause.getMessage();
    this.errorCode = errorCode;
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }

  public String getErrorMessage() {
    return errorMessage;
  }

}
