/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.api;

/**
 * @author Lijun Liao
 */

public class OperationException extends Exception
{
    public static enum ErrorCode
    {
        ALREADY_ISSUED,
        BAD_CERT_TEMPLATE,
        CERT_REVOKED,
        CERT_UNREVOKED,
        CRL_FAILURE,
        DATABASE_FAILURE,
        INSUFFICIENT_PERMISSION,
        INVALID_EXTENSION,
        NOT_PERMITTED,
        System_Failure,
        UNKNOWN_CERT,
        UNKNOWN_CERT_PROFILE
    }

    private static final long serialVersionUID = 1L;

    private final ErrorCode errorCode;
    private final String errorMessage;

    public OperationException(ErrorCode errorCode)
    {
        super("error code: " + errorCode);
        this.errorCode = errorCode;
        this.errorMessage = null;
    }

    public OperationException(ErrorCode errorCode, String errorMessage)
    {
        super("error code: " + errorCode + ", error message: " + errorMessage);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public ErrorCode getErrorCode()
    {
        return errorCode;
    }

    public String getErrorMessage()
    {
        return errorMessage;
    }

}
