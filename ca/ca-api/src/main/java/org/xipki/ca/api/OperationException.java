/*
 * Copyright 2014 xipki.org
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

public class OperationException extends Exception
{
    public static enum ErrorCode
    {
        UNKNOWN_ISSUER,
        UNKNOWN_CERT_PROFILE,
        NO_PERMISSION_OF_CERT_PROFILE,
        EMPTY_SUBJECT,
        CERT_REVOKED,
        UNKNOWN_CERT,
        System_Failure,
        ALREADY_ISSUED,
        BAD_CERT_TEMPLATE
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
        super("error code: " + errorCode + "\nerror message: " + errorMessage);
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
