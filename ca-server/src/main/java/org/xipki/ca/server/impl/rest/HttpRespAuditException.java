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

package org.xipki.ca.server.impl.rest;

import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpRespAuditException extends Exception {

    // Field descriptor #5 I
    public static final int SC_CONTINUE = 100;

    // Field descriptor #5 I
    public static final int SC_SWITCHING_PROTOCOLS = 101;

    // Field descriptor #5 I
    public static final int SC_OK = 200;

    // Field descriptor #5 I
    public static final int SC_CREATED = 201;

    // Field descriptor #5 I
    public static final int SC_ACCEPTED = 202;

    // Field descriptor #5 I
    public static final int SC_NON_AUTHORITATIVE_INFORMATION = 203;

    // Field descriptor #5 I
    public static final int SC_NO_CONTENT = 204;

    // Field descriptor #5 I
    public static final int SC_RESET_CONTENT = 205;

    // Field descriptor #5 I
    public static final int SC_PARTIAL_CONTENT = 206;

    // Field descriptor #5 I
    public static final int SC_MULTIPLE_CHOICES = 300;

    // Field descriptor #5 I
    public static final int SC_MOVED_PERMANENTLY = 301;

    // Field descriptor #5 I
    public static final int SC_MOVED_TEMPORARILY = 302;

    // Field descriptor #5 I
    public static final int SC_FOUND = 302;

    // Field descriptor #5 I
    public static final int SC_SEE_OTHER = 303;

    // Field descriptor #5 I
    public static final int SC_NOT_MODIFIED = 304;

    // Field descriptor #5 I
    public static final int SC_USE_PROXY = 305;

    // Field descriptor #5 I
    public static final int SC_TEMPORARY_REDIRECT = 307;

    // Field descriptor #5 I
    public static final int SC_BAD_REQUEST = 400;

    // Field descriptor #5 I
    public static final int SC_UNAUTHORIZED = 401;

    // Field descriptor #5 I
    public static final int SC_PAYMENT_REQUIRED = 402;

    // Field descriptor #5 I
    public static final int SC_FORBIDDEN = 403;

    // Field descriptor #5 I
    public static final int SC_NOT_FOUND = 404;

    // Field descriptor #5 I
    public static final int SC_METHOD_NOT_ALLOWED = 405;

    // Field descriptor #5 I
    public static final int SC_NOT_ACCEPTABLE = 406;

    // Field descriptor #5 I
    public static final int SC_PROXY_AUTHENTICATION_REQUIRED = 407;

    // Field descriptor #5 I
    public static final int SC_REQUEST_TIMEOUT = 408;

    // Field descriptor #5 I
    public static final int SC_CONFLICT = 409;

    // Field descriptor #5 I
    public static final int SC_GONE = 410;

    // Field descriptor #5 I
    public static final int SC_LENGTH_REQUIRED = 411;

    // Field descriptor #5 I
    public static final int SC_PRECONDITION_FAILED = 412;

    // Field descriptor #5 I
    public static final int SC_REQUEST_ENTITY_TOO_LARGE = 413;

    // Field descriptor #5 I
    public static final int SC_REQUEST_URI_TOO_LONG = 414;

    // Field descriptor #5 I
    public static final int SC_UNSUPPORTED_MEDIA_TYPE = 415;

    // Field descriptor #5 I
    public static final int SC_REQUESTED_RANGE_NOT_SATISFIABLE = 416;

    // Field descriptor #5 I
    public static final int SC_EXPECTATION_FAILED = 417;

    // Field descriptor #5 I
    public static final int SC_INTERNAL_SERVER_ERROR = 500;

    // Field descriptor #5 I
    public static final int SC_NOT_IMPLEMENTED = 501;

    // Field descriptor #5 I
    public static final int SC_BAD_GATEWAY = 502;

    // Field descriptor #5 I
    public static final int SC_SERVICE_UNAVAILABLE = 503;

    // Field descriptor #5 I
    public static final int SC_GATEWAY_TIMEOUT = 504;

    // Field descriptor #5 I
    public static final int SC_HTTP_VERSION_NOT_SUPPORTED = 505;

    private static final long serialVersionUID = 1L;

    private final int httpStatus;

    private final String httpErrorMessage;

    private final String auditMessage;

    private final AuditLevel auditLevel;

    private AuditStatus auditStatus;

    public HttpRespAuditException(int httpStatus, String auditMessage,
            AuditLevel auditLevel, AuditStatus auditStatus) {
        this(httpStatus, null, auditMessage, auditLevel, auditStatus);
    }

    public HttpRespAuditException(int httpStatus, String httpErrorMessage,
            String auditMessage, AuditLevel auditLevel, AuditStatus auditStatus) {
        this.httpStatus = httpStatus;
        this.httpErrorMessage = httpErrorMessage;
        this.auditMessage = ParamUtil.requireNonBlank("auditMessage", auditMessage);
        this.auditLevel = ParamUtil.requireNonNull("auditLevel", auditLevel);
        this.auditStatus = ParamUtil.requireNonNull("auditStatus", auditStatus);
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String httpErrorMessage() {
        return httpErrorMessage;
    }

    public String auditMessage() {
        return auditMessage;
    }

    public AuditLevel auditLevel() {
        return auditLevel;
    }

    public AuditStatus auditStatus() {
        return auditStatus;
    }

}
