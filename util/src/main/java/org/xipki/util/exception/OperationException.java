/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.util.exception;

/**
 * Operation exception.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OperationException extends Exception {

  public enum ErrorCode {

    ALREADY_ISSUED (1),
    BAD_CERT_TEMPLATE (2),
    BAD_REQUEST (3),
    BAD_POP (4),
    CERT_REVOKED (5),
    CERT_UNREVOKED (6),
    CRL_FAILURE (7),
    DATABASE_FAILURE (8),
    INVALID_EXTENSION (9),
    NOT_PERMITTED (10),
    SYSTEM_FAILURE (11),
    SYSTEM_UNAVAILABLE (12),
    UNKNOWN_CERT (13),
    UNKNOWN_CERT_PROFILE (14),
    PATH_NOT_FOUND (15),
    UNAUTHORIZED (16);

    private int code;

    ErrorCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static ErrorCode ofCode(int code) {
      for (ErrorCode ec : values()) {
        if (ec.code == code) {
          return ec;
        }
      }
      throw new IllegalArgumentException("unknown code " + code);
    }
  } // class ErrorCode

  private static final long serialVersionUID = 1L;

  private final ErrorCode errorCode;

  private final String errorMessage;

  public OperationException(ErrorCode errorCode) {
    super(String.format("error code: %s", errorCode));
    this.errorCode = errorCode;
    this.errorMessage = null;
  }

  public OperationException(ErrorCode errorCode, String errorMessage) {
    super(String.format("error code: %s, error message: %s", errorCode, errorMessage));
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
  }

  public OperationException(ErrorCode errorCode, Throwable throwable) {
    this(errorCode, getMessage(throwable));
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }

  public String getErrorMessage() {
    return errorMessage;
  }

  private static String getMessage(Throwable throwable) {
    if (throwable == null) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    sb.append(throwable.getClass().getSimpleName());
    String msg = throwable.getMessage();
    if (msg != null) {
      sb.append(": ").append(msg);
    }
    return sb.toString();
  } // method getMessage

}
