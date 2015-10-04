/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.client.api;

import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.xipki.security.api.util.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class PKIErrorException extends Exception {
    private static final long serialVersionUID = 1L;

    private final int status;
    private final int pkiFailureInfo;
    private final String statusMessage;

    public PKIErrorException(
            final PKIStatusInfo statusInfo) {
        this(new org.xipki.pki.ca.common.cmp.PKIStatusInfo(statusInfo));
    }

    public PKIErrorException(
            final org.xipki.pki.ca.common.cmp.PKIStatusInfo statusInfo) {
        this(statusInfo.getStatus(), statusInfo.getPkiFailureInfo(), statusInfo.getStatusMessage());
    }

    public PKIErrorException(
            final int status,
            final int pkiFailureInfo,
            final String statusMessage) {
        super(SecurityUtil.formatPKIStatusInfo(status, pkiFailureInfo, statusMessage));
        this.status = status;
        this.pkiFailureInfo = pkiFailureInfo;
        this.statusMessage = statusMessage;
    }

    public PKIErrorException(
            final int status) {
        this.status = status;
        this.pkiFailureInfo = 0;
        this.statusMessage = null;
    }

    public int getStatus() {
        return status;
    }

    public int getPkiFailureInfo() {
        return pkiFailureInfo;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

}
