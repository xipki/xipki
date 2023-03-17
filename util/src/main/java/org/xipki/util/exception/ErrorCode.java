// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.exception;

/**
 * Error code.
 * @author Lijun Liao (xipki)
 */
public enum ErrorCode {

  ALREADY_ISSUED(1),
  BAD_CERT_TEMPLATE(2),
  BAD_REQUEST(3),
  BAD_POP(4),
  CERT_REVOKED(5),
  CERT_UNREVOKED(6),
  CRL_FAILURE(7),
  DATABASE_FAILURE(8),
  INVALID_EXTENSION(9),
  NOT_PERMITTED(10),
  SYSTEM_FAILURE(11),
  SYSTEM_UNAVAILABLE(12),
  UNKNOWN_CERT(13),
  UNKNOWN_CERT_PROFILE(14),
  PATH_NOT_FOUND(15),
  UNAUTHORIZED(16);

  private final int code;

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
