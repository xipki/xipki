/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.api;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OperationException extends Exception {

    public enum ErrorCode {

        ALREADY_ISSUED,
        BAD_CERT_TEMPLATE,
        BAD_REQUEST,
        BAD_POP,
        CERT_REVOKED,
        CERT_UNREVOKED,
        CRL_FAILURE,
        DATABASE_FAILURE,
        INVALID_EXTENSION,
        NOT_PERMITTED,
        SYSTEM_FAILURE,
        SYSTEM_UNAVAILABLE,
        UNKNOWN_CERT,
        UNKNOWN_CERT_PROFILE

    } // enum ErrorCode

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

    public ErrorCode errorCode() {
        return errorCode;
    }

    public String errorMessage() {
        return errorMessage;
    }

    private static final String getMessage(Throwable throwable) {
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
    }

}
