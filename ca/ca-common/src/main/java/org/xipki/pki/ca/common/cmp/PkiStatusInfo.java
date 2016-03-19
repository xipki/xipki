/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.pki.ca.common.cmp;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.util.CmpFailureUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PkiStatusInfo {

    private final int status;

    private final int pkiFailureInfo;

    private final String statusMessage;

    public PkiStatusInfo(
            final int status,
            final int pkiFailureInfo,
            final String statusMessage) {
        this.status = status;
        this.pkiFailureInfo = pkiFailureInfo;
        this.statusMessage = statusMessage;
    }

    public PkiStatusInfo(
            final int status) {
        this.status = status;
        this.pkiFailureInfo = 0;
        this.statusMessage = null;
    }

    public PkiStatusInfo(
            final org.bouncycastle.asn1.cmp.PKIStatusInfo bcPkiStatusInfo) {
        ParamUtil.requireNonNull("bcPkiStatusInfo", bcPkiStatusInfo);

        this.status = bcPkiStatusInfo.getStatus().intValue();
        if (bcPkiStatusInfo.getFailInfo() != null) {
            this.pkiFailureInfo = bcPkiStatusInfo.getFailInfo().intValue();
        } else {
            this.pkiFailureInfo = 0;
        }
        PKIFreeText text = bcPkiStatusInfo.getStatusString();
        this.statusMessage = (text == null)
                ? null
                : text.getStringAt(0).getString();
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

    @Override
    public String toString() {
        return CmpFailureUtil.formatPkiStatusInfo(status, pkiFailureInfo, statusMessage);
    }

}
