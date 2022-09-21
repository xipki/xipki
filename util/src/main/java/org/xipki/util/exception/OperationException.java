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
    this(errorCode, throwable.getMessage());
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }

  public String getErrorMessage() {
    return errorMessage;
  }

}
