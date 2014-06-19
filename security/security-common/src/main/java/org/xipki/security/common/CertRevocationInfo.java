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

package org.xipki.security.common;

import java.util.Date;

/**
 * @author Lijun Liao
 */

public class CertRevocationInfo
{
    private CRLReason reason;
    private Date revocationTime;
    private Date invalidityTime;

    public CertRevocationInfo(CRLReason reason)
    {
        this(reason, null, null);
    }

    public CertRevocationInfo(int reasonCode)
    {
        this(reasonCode, null, null);
    }

    public CertRevocationInfo(CRLReason reason, Date revocationTime, Date invalidityTime)
    {
        ParamChecker.assertNotNull("reason", reason);
        this.reason = reason;
        this.revocationTime = revocationTime;
        this.invalidityTime = invalidityTime;
    }

    public CertRevocationInfo(int reasonCode, Date revocationTime, Date invalidityTime)
    {
        this.reason = CRLReason.forReasonCode(reasonCode);
        if(this.reason == null)
        {
            throw new IllegalArgumentException("invalid reason " + reasonCode);
        }
        this.revocationTime = revocationTime;
        this.invalidityTime = invalidityTime;
    }

    public void setReason(CRLReason reason)
    {
        ParamChecker.assertNotNull("reason", reason);
        this.reason = reason;
    }

    public CRLReason getReason()
    {
        return reason;
    }

    public void setRevocationTime(Date revocationTime)
    {
        this.revocationTime = revocationTime;
    }

    /**
     *
     * @return revocation time, never be null
     */
    public Date getRevocationTime()
    {
        if(revocationTime == null)
        {
            revocationTime = new Date();
        }
        return revocationTime;
    }

    /**
     *
     * @return invalidity time, may be null
     */
    public Date getInvalidityTime()
    {
        return invalidityTime;
    }

    public void setInvalidityTime(Date invalidityTime)
    {
        this.invalidityTime = invalidityTime;
    }

}
