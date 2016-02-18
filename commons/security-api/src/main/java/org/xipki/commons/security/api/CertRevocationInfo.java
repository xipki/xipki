/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.api;

import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertRevocationInfo implements Serializable {

    //------------------------------------------------
    // Customized serialization
    //------------------------------------------------
    private static final long serialVersionUID = 1L;

    private static final String SR_SERIAL_VERSION = "serialVersion";
    private static final double SERIAL_VERSION = 1.0;

    private static final String SR_REASON = "reason";
    private static final String SR_REVOCATION_TIME = "revocationTime";
    private static final String SR_INVALIDITY_TIME = "invalidityTime";

    private double serialVersion;

    private CrlReason reason;

    private Date revocationTime;

    private Date invalidityTime;

    public CertRevocationInfo(
            final CrlReason reason) {
        this(reason, new Date(), null);
    }

    public CertRevocationInfo(
            final int reasonCode) {
        this(reasonCode, new Date(), null);
    }

    public CertRevocationInfo(
            final CrlReason reason,
            final Date revocationTime,
            final Date invalidityTime) {
        ParamUtil.assertNotNull("reason", reason);
        ParamUtil.assertNotNull("revocationTime", revocationTime);
        this.reason = reason;
        this.revocationTime = revocationTime;
        this.invalidityTime = invalidityTime;
        this.serialVersion = SERIAL_VERSION;
    }

    public CertRevocationInfo(
            final int reasonCode,
            final Date revocationTime,
            final Date invalidityTime) {
        ParamUtil.assertNotNull("revocationTime", revocationTime);

        this.reason = CrlReason.forReasonCode(reasonCode);
        if (this.reason == null) {
            throw new IllegalArgumentException("invalid reason " + reasonCode);
        }
        this.revocationTime = revocationTime;
        this.invalidityTime = invalidityTime;
        this.serialVersion = SERIAL_VERSION;
    }

    public void setReason(
            final CrlReason reason) {
        ParamUtil.assertNotNull("reason", reason);
        this.reason = reason;
    }

    public CrlReason getReason() {
        return reason;
    }

    public void setRevocationTime(
            final Date revocationTime) {
        this.revocationTime = revocationTime;
    }

    /**
     *
     * @return revocation time, never be null
     */
    public Date getRevocationTime() {
        if (revocationTime == null) {
            revocationTime = new Date();
        }
        return revocationTime;
    }

    /**
     *
     * @return invalidity time, may be null
     */
    public Date getInvalidityTime() {
        return invalidityTime;
    }

    public void setInvalidityTime(
            final Date invalidityTime) {
        this.invalidityTime = invalidityTime;
    }

    private void writeObject(
            final java.io.ObjectOutputStream out)
    throws IOException {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_SERIAL_VERSION, serialVersion);
        serialMap.put(SR_REASON, reason);
        serialMap.put(SR_REVOCATION_TIME, revocationTime);
        serialMap.put(SR_INVALIDITY_TIME, invalidityTime);

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(
            final java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_SERIAL_VERSION);
        reason = (CrlReason) serialMap.get(SR_REASON);
        revocationTime = (Date) serialMap.get(SR_REVOCATION_TIME);
        invalidityTime = (Date) serialMap.get(SR_INVALIDITY_TIME);
    }

}
