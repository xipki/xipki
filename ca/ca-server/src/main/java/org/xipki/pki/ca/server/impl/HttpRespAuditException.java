/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.impl;

import org.xipki.commons.audit.AuditLevel;
import org.xipki.commons.audit.AuditStatus;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class HttpRespAuditException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int httpStatus;

    private final String httpErrorMessage;

    private final String auditMessage;

    private final AuditLevel auditLevel;

    private final AuditStatus auditStatus;

    public HttpRespAuditException(final int httpStatus, final String auditMessage,
            final AuditLevel auditLevel, final AuditStatus auditStatus) {
        this(httpStatus, null, auditMessage, auditLevel, auditStatus);
    }

    public HttpRespAuditException(final int httpStatus, final String httpErrorMessage,
            final String auditMessage, final AuditLevel auditLevel, final AuditStatus auditStatus) {
        this.httpStatus = httpStatus;
        this.httpErrorMessage = httpErrorMessage;
        this.auditMessage = ParamUtil.requireNonBlank("auditMessage", auditMessage);
        this.auditLevel = ParamUtil.requireNonNull("auditLevel", auditLevel);
        this.auditStatus = ParamUtil.requireNonNull("auditStatus", auditStatus);
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getHttpErrorMessage() {
        return httpErrorMessage;
    }

    public String getAuditMessage() {
        return auditMessage;
    }

    public AuditLevel getAuditLevel() {
        return auditLevel;
    }

    public AuditStatus getAuditStatus() {
        return auditStatus;
    }

}
