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

package org.xipki.security;

import java.util.Date;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertRevocationInfo {

    private CrlReason reason;

    private Date revocationTime;

    private Date invalidityTime;

    public CertRevocationInfo(CrlReason reason) {
        this(reason, new Date(), null);
    }

    public CertRevocationInfo(int reasonCode) {
        this(reasonCode, new Date(), null);
    }

    public CertRevocationInfo(CrlReason reason, Date revocationTime, Date invalidityTime) {
        this.reason = ParamUtil.requireNonNull("reason", reason);
        this.revocationTime = ParamUtil.requireNonNull("revocationTime", revocationTime);
        this.invalidityTime = invalidityTime;
    }

    public CertRevocationInfo(int reasonCode, Date revocationTime, Date invalidityTime) {
        this.revocationTime = ParamUtil.requireNonNull("revocationTime", revocationTime);
        this.reason = CrlReason.forReasonCode(reasonCode);
        this.invalidityTime = invalidityTime;
    }

    public void setReason(CrlReason reason) {
        this.reason = ParamUtil.requireNonNull("reason", reason);
    }

    public CrlReason reason() {
        return reason;
    }

    public void setRevocationTime(Date revocationTime) {
        this.revocationTime = revocationTime;
    }

    /**
     * Gets the revocation time.
     * @return revocation time, never be null
     */
    public Date revocationTime() {
        if (revocationTime == null) {
            revocationTime = new Date();
        }
        return revocationTime;
    }

    /**
     * Get the invalidity time.
     * @return invalidity time, may be null
     */
    public Date invalidityTime() {
        return invalidityTime;
    }

    public void setInvalidityTime(Date invalidityTime) {
        this.invalidityTime = invalidityTime;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("reason: ").append(reason).append("\n");
        sb.append("revocationTime: ").append(revocationTime).append("\n");
        sb.append("invalidityTime: ").append(invalidityTime);
        return sb.toString();
    }

}
