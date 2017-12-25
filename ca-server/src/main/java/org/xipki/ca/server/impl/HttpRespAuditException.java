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

package org.xipki.ca.server.impl;

import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.common.util.ParamUtil;

import io.netty.handler.codec.http.HttpResponseStatus;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class HttpRespAuditException extends Exception {

    private static final long serialVersionUID = 1L;

    private final HttpResponseStatus httpStatus;

    private final String httpErrorMessage;

    private final String auditMessage;

    private final AuditLevel auditLevel;

    private final AuditStatus auditStatus;

    public HttpRespAuditException(final HttpResponseStatus httpStatus, final String auditMessage,
            final AuditLevel auditLevel, final AuditStatus auditStatus) {
        this(httpStatus, null, auditMessage, auditLevel, auditStatus);
    }

    public HttpRespAuditException(final HttpResponseStatus httpStatus, final String httpErrorMessage,
            final String auditMessage, final AuditLevel auditLevel, final AuditStatus auditStatus) {
        this.httpStatus = httpStatus;
        this.httpErrorMessage = httpErrorMessage;
        this.auditMessage = ParamUtil.requireNonBlank("auditMessage", auditMessage);
        this.auditLevel = ParamUtil.requireNonNull("auditLevel", auditLevel);
        this.auditStatus = ParamUtil.requireNonNull("auditStatus", auditStatus);
    }

    public HttpResponseStatus httpStatus() {
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
